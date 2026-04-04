#pragma once

//  Interface — binds to a NIC and owns the send/capture lifecycle.
//
//  the NIC operates at L2. every send path ultimately produces a complete
//  Ethernet frame before hitting sendto(). the overloads exist only to
//  spare the user from manually constructing lower layers:
//
//    write(Ether)          → frame already complete, send as-is
//    write(IPv4|IPv6|ARP)  → Interface prepends Ether, resolves MACs
//
//  capture always delivers a complete Ether frame to the callback — the user
//  can pull out any layer they care about via frame.layer<IPv4>() etc.

#include "lynx/config.hpp"
#include "lynx/core/error.hpp"
#include "lynx/core/constants.hpp"
#include "lynx/core/buffer.hpp"
#include "lynx/protocols/all.hpp"

#include "./socket.hpp"

#include <atomic>
#include <functional>
#include <cstdint>

namespace lynx::io {

//  RecvAction — returned by the recv callback to control the loop

enum class RecvAction : uint8_t {
    Continue = 0,   // keep looping
    Stop     = 1,   // exit recv loop cleanly
};

//  Interface
class Interface : public BaseObject {
    public:

        // ── construction

        explicit Interface(const char* name) noexcept
            : name_(name) {}

        // destructor behaviour controlled by LYNX_CLOSE_ON_DESTROY in config.hpp
        ~Interface() noexcept {
            #if LYNX_CLOSE_ON_DESTROY == 1
                if (is_open()) {
                    if (promisc_) sock::set_promiscuous(fd_, ifindex_, false);
                    sock::close_fd(fd_);
                }
            #endif
        }

        // non-copyable — owns a file descriptor
        Interface(const Interface&)            = delete;
        Interface& operator=(const Interface&) = delete;

        // movable
        Interface(Interface&& o) noexcept
            : name_(o.name_), fd_(o.fd_), ifindex_(o.ifindex_)
            , promisc_(o.promisc_), snaplen_(o.snaplen_)
            , timeout_ms_(o.timeout_ms_), direction_(o.direction_)
            , rcvbuf_size_(o.rcvbuf_size_), stop_(o.stop_.load())
        {
            o.fd_      = sock::INVALID_FD;
            o.ifindex_ = sock::INVALID_IDX;
        }

        // ── lifecycle 

        // open() creates the socket, resolves the interface index, binds,
        // and flushes all pending tuning options queued before open().
        void open() noexcept
        {
            if (is_open()) {
                set_error(Status::IfaceAlreadyOpen, "interface already open");
                return;
            }

            absorb(sock::open_raw(fd_));                      if (!ok()) return;
            absorb(sock::resolve_ifindex(name_, ifindex_));   if (!ok()) return;
            absorb(sock::bind_to_iface(fd_, ifindex_));       if (!ok()) return;
            absorb(sock::set_recv_timeout(fd_, timeout_ms_)); if (!ok()) return;
            absorb(sock::set_recv_buffer(fd_, rcvbuf_size_)); if (!ok()) return;
            absorb(sock::set_direction(fd_, direction_));     if (!ok()) return;

            if (promisc_)
                absorb(sock::set_promiscuous(fd_, ifindex_, true));
        }

        // close() removes promiscuous mode if active, then closes the fd.
        // safe to call multiple times.
        void close() noexcept
        {
            if (!is_open()) return;
            if (promisc_) sock::set_promiscuous(fd_, ifindex_, false);
            sock::close_fd(fd_);
            ifindex_ = sock::INVALID_IDX;
        }

        [[nodiscard]] bool is_open() const noexcept { return fd_ != sock::INVALID_FD; }

        // ── tuning 
        // can be called before or after open().
        // if called after open(), the option is applied to the live socket immediately.
        // if called before open(), stored and flushed at open().

        void set_promiscuous(bool enable) noexcept
        {
            promisc_ = enable;
            if (is_open())
                absorb(sock::set_promiscuous(fd_, ifindex_, enable));
        }

        void set_snaplen(int bytes) noexcept
        {
            if (bytes <= 0) { set_error(Status::InvalidArgument, "snaplen must be > 0"); return; }
            snaplen_ = bytes;
        }

        void set_timeout(int ms) noexcept
        {
            if (ms < 0) { set_error(Status::InvalidArgument, "timeout must be >= 0"); return; }
            timeout_ms_ = ms;
            if (is_open()) absorb(sock::set_recv_timeout(fd_, ms));
        }

        void set_direction(sock::Direction dir) noexcept
        {
            direction_ = dir;
            if (is_open()) absorb(sock::set_direction(fd_, dir));
        }

        void set_buffer_size(int bytes) noexcept
        {
            if (bytes < 0) { set_error(Status::InvalidArgument, "buffer size must be >= 0"); return; }
            rcvbuf_size_ = bytes;
            if (is_open()) absorb(sock::set_recv_buffer(fd_, bytes));
        }

        // ── send overloads 

        // L2 — complete frame, sent as-is, no MAC resolution
        void write(const proto::Frame& frame) noexcept {
            if (!check_open()) return;

            Buffer buf = Buffer::alloc(frame.size());
            if (!buf.ok()) { absorb(buf.error()); return; }

            frame.serialize(buf);
            if (!frame.ok()) { absorb(frame.error()); return; }

            // dst MAC sits at offset 0 in every L2 frame (HdrEth / HdrDot1Q)
            absorb(sock::raw_send(fd_, ifindex_, buf.begin(), buf.len(),
                                buf.begin()));
        }

        // L3 — any Packet (IPv4, IPv6, ARP)
        // ethertype / dst MAC / broadcast policy driven by Packet virtuals
        void write(proto::Packet& pkt) noexcept {
            write_l3_(pkt);
        }

        // ── capture 

        // blocking loop — single Buffer allocation reused every iteration.
        // callback receives a RawFrame — owns raw bytes, exposes type().
        // user calls raw.as<Ether>() or raw.as<Dot1Q>() for typed access.
        void capture(capture_callback_t cb) noexcept {
            if (!check_open()) return;
    
            stop_.store(false);
    
            Buffer buf = Buffer::alloc(static_cast<uint32_t>(snaplen_));
            if (!buf.ok()) { absorb(buf.error()); return; }

            Error   recv_err;
    
            while (!stop_.load()) {
                buf.reset();
    
                int32_t n = sock::raw_recv(fd_, buf.begin(), buf.cap(),
                                            nullptr, recv_err);
                if (n < 0)  { absorb(recv_err); return; }  // hard error — exit
                if (n == 0) continue;                       // EAGAIN — check stop_
    
                // RawFrame wraps buf's slab with a no-op deleter — buf_ keeps
                // the slab alive for the duration of the callback. safe because
                // buf.reset() is not called until the next iteration.
                proto::RawFrame raw;
                raw.dissect(buf.begin(), static_cast<uint32_t>(n));
                if (!raw.ok()) continue;                    // malformed — skip
    
                if (cb(raw) == RecvAction::Stop) return;
            }
        }

        // thread-safe stop — capture exits on next timeout tick
        void stop() noexcept { stop_.store(true); }

        // ── accessors 

        [[nodiscard]] const char* name()    const noexcept { return name_;    }
        [[nodiscard]] int         fd()      const noexcept { return fd_;      }
        [[nodiscard]] int         ifindex() const noexcept { return ifindex_; }

    private:

        // ── write_l3_ 
        // single implementation for all L3 send paths.
        // all policy decisions come from Packet virtuals — no type switching.
        // using Ethernet as default protocol in case no L2 header provided
        void write_l3_(proto::Packet& pkt) noexcept {
            if (!check_open()) return;          // guard first

            proto::Ether eth;

            eth.hdr()->ethertype = pkt.ethertype();

            if (pkt.is_broadcast()) {
                __builtin_memset(eth.hdr()->dst_mac, 0xff, 6);
                if (!resolve_src_mac(eth.hdr())) return;
            } else {
                if (!resolve_ether(eth, pkt.dst())) return;
            }

            Buffer buf = Buffer::alloc(eth.size() + pkt.size());

            if (!buf.ok()) { 
                absorb(buf.error()); 
                return; 
            }

            // include pkt inside ethernet (patch checksum called explicitly)
            eth / pkt;

            eth.serialize(buf);

            if (!pkt.ok()) { absorb(pkt.error()); return; }

            absorb(sock::raw_send(fd_, ifindex_, buf.begin(), buf.len(),
                                eth.hdr()->dst_mac));
        }

        [[nodiscard]] bool check_open() noexcept {
            if (!is_open()) { set_error(Status::IfaceNotOpen, "interface not open"); return false; }
            return true;
        }

        // fills eth.src per LYNX_SRC_MAC_POLICY in config.hpp
        [[nodiscard]] bool resolve_src_mac(hdrs::HdrEth* eth) noexcept {
            #if LYNX_SRC_MAC_POLICY == 1
                absorb(sock::get_iface_mac(fd_, name_, eth->src_mac));
            #elif LYNX_SRC_MAC_POLICY == 2
                absorb(sock::randomize_mac(eth->src_mac));
            #endif
                    return ok();
        }

        // fills eth.src and eth.dst for unicast IPv4 targets
        [[nodiscard]] bool resolve_ether(proto::Ether& eth, const uint8_t dst_ip[4]) noexcept {
            if (!resolve_src_mac(eth.hdr())) return false;

            #if LYNX_DST_MAC_POLICY == 1
                    __builtin_memset(eth.hdr()->dst_mac, 0xff, 6);             // broadcast
            #elif LYNX_DST_MAC_POLICY == 2
                    absorb(arp_lookup(dst_ip, eth.hdr()->dst_mac));             // kernel ARP cache
            #endif
                return ok();
        }

        // SIOCGARP — kernel ARP cache lookup for dst_ip → out_mac
        // v1: replace with active ARP probe + timeout
        [[nodiscard]] Error arp_lookup(const uint8_t dst_ip[4],
                        uint8_t       out_mac[6]) noexcept {
            return sock::arp_lookup(fd_, name_, dst_ip, out_mac);
        }

        // ── member state 

        const char*       name_        = nullptr;
        int               fd_          = sock::INVALID_FD;
        int               ifindex_     = sock::INVALID_IDX;

        bool              promisc_     = false;
        int               snaplen_     = LYNX_DEFAULT_SNAPLEN;
        int               timeout_ms_  = LYNX_DEFAULT_TIMEOUT_MS;
        sock::Direction   direction_   = sock::Direction::Both;
        int               rcvbuf_size_ = LYNX_RECV_BUFFER_SIZE;

        std::atomic<bool> stop_{ false };
    };

} // namespace lynx

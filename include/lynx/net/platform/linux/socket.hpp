#pragma once

//  raw AF_PACKET socket primitives.
//  all functions are free stateless helpers — no class, no vtable.
//  every function returns Error. caller checks .ok() and absorbs if needed.

#include "lynx/core/base.hpp"
#include "lynx/config.hpp"

#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if_arp.h>
#include <netinet/in.h>


namespace lynx::sock {

static constexpr int INVALID_FD  = -1;
static constexpr int INVALID_IDX = -1;

//  direction — controls which frames recvfrom delivers

enum class Direction : uint8_t {
    In   = 0,   // incoming frames only
    Out  = 1,   // outgoing frames only (filtered in recv loop)
    Both = 2,   // default — all frames
};

//  open_raw()
//  creates AF_PACKET / SOCK_RAW socket that captures all ethertypes.
//  writes valid fd into fd on success, INVALID_FD on failure.

[[nodiscard]] inline Error open_raw(int& fd) noexcept
{
    fd = ::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        fd = INVALID_FD;
        return Error::make(Status::SocketCreateFail, ::strerror(errno));
    }
    return Error::none();
}

//  resolve_ifindex()
//  maps interface name → kernel interface index.
//  writes valid index into idx on success, INVALID_IDX on failure.

[[nodiscard]] inline Error resolve_ifindex(const char* name,
                                            int&        idx) noexcept
{
    unsigned i = ::if_nametoindex(name);
    if (i == 0) {
        idx = INVALID_IDX;
        return Error::make(Status::IfaceNotFound,
                           "if_nametoindex() failed: interface not found");
    }
    idx = static_cast<int>(i);
    return Error::none();
}

//  bind_to_iface()
//  binds fd to a specific interface so only its frames are received.

[[nodiscard]] inline Error bind_to_iface(int fd, int ifindex) noexcept
{
    ::sockaddr_ll sll{};
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex  = ifindex;

    if (::bind(fd,
               reinterpret_cast<const ::sockaddr*>(&sll),
               sizeof(sll)) < 0)
    {
        return Error::make(Status::SocketBindFail, ::strerror(errno));
    }
    return Error::none();
}

//  set_promiscuous()
//  enters or leaves promiscuous mode on ifindex.
//  always call with enable=false before closing to clean up NIC state.

[[nodiscard]] inline Error set_promiscuous(int  fd,
                                            int  ifindex,
                                            bool enable) noexcept
{
    ::packet_mreq mreq{};
    mreq.mr_ifindex = ifindex;
    mreq.mr_type    = PACKET_MR_PROMISC;

    int opt = enable ? PACKET_ADD_MEMBERSHIP : PACKET_DROP_MEMBERSHIP;

    if (::setsockopt(fd, SOL_PACKET, opt, &mreq, sizeof(mreq)) < 0)
        return Error::make(Status::SocketOptionFail, ::strerror(errno));

    return Error::none();
}

//  set_recv_timeout()
//  SO_RCVTIMEO — recvfrom wakes every timeout_ms to check stop flag.
//  timeout_ms = 0 → recvfrom blocks indefinitely (not recommended).

[[nodiscard]] inline Error set_recv_timeout(int fd, int timeout_ms) noexcept
{
    ::timeval tv{};
    tv.tv_sec  =  timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    if (::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
        return Error::make(Status::SocketOptionFail, ::strerror(errno));

    return Error::none();
}

//  set_recv_buffer()
//  SO_RCVBUF — kernel-side ring buffer size in bytes.
//  size_bytes = 0 → leave at kernel default, returns Error::none() early.

[[nodiscard]] inline Error set_recv_buffer(int fd, int size_bytes) noexcept
{
    if (size_bytes == 0) return Error::none();

    if (::setsockopt(fd, SOL_SOCKET, SO_RCVBUF,
                     &size_bytes, sizeof(size_bytes)) < 0)
        return Error::make(Status::SocketOptionFail, ::strerror(errno));

    return Error::none();
}

//  set_direction()
//  Direction::In  — PACKET_IGNORE_OUTGOING=1, drops outgoing frames.
//  Direction::Out — no kernel option, recv loop filters by sll_pkttype.
//  Direction::Both — default, PACKET_IGNORE_OUTGOING=0.

[[nodiscard]] inline Error set_direction(int fd, Direction dir) noexcept
{
    int ignore_out = (dir == Direction::In) ? 1 : 0;

    if (dir != Direction::Out) {
        if (::setsockopt(fd, SOL_PACKET, PACKET_IGNORE_OUTGOING,
                         &ignore_out, sizeof(ignore_out)) < 0)
            return Error::make(Status::SocketOptionFail, ::strerror(errno));
    }
    return Error::none();
}

//  get_iface_mac()
//  SIOCGIFHWADDR — reads hardware MAC of interface into out_mac[6].

[[nodiscard]] inline Error get_iface_mac(int           fd,
                                          const char*   name,
                                          uint8_t       out_mac[6]) noexcept
{
    ::ifreq ifr{};
    __builtin_strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);

    if (::ioctl(fd, SIOCGIFHWADDR, &ifr) < 0)
        return Error::make(Status::MacResolveFail, ::strerror(errno));

    __builtin_memcpy(out_mac, ifr.ifr_hwaddr.sa_data, 6);
    return Error::none();
}

//  arp_lookup()
//  SIOCGARP — queries kernel ARP cache for dst_ip, writes MAC into out_mac.
//
//  fd      — any open AF_PACKET socket (does not have to be bound)
//  iface   — interface name to scope the lookup (avoids cross-iface hits)
//  dst_ip  — 4-byte IPv4 target address in network byte order
//  out_mac — 6-byte output buffer, written on success only
//
//  returns ArpResolveFail if:
//    - entry is absent from cache (host never seen / TTL expired)
//    - entry exists but ATF_COM is not set (kernel sent ARP req, no reply yet)
//
//  note: this is a pure cache lookup — no packets are sent.
//  active ARP probing (send request, wait for reply) is a v1 feature.
 
[[nodiscard]] inline Error arp_lookup(int           fd,
                                       const char*   iface,
                                       const uint8_t dst_ip[4],
                                       uint8_t       out_mac[6]) noexcept
{
    if (!dst_ip || !out_mac)
        return Error::make(Status::InvalidArgument,
                           "arp_lookup: null dst_ip or out_mac");
 
    ::arpreq req{};
 
    // target IP — stored in arp_pa as sockaddr_in
    auto* sin = reinterpret_cast<::sockaddr_in*>(&req.arp_pa);
    sin->sin_family = AF_INET;
    __builtin_memcpy(&sin->sin_addr.s_addr, dst_ip, 4);
 
    // scope to interface — without this the kernel may return an entry
    // from a different NIC that has the same IP in its cache
    __builtin_strncpy(req.arp_dev, iface, sizeof(req.arp_dev) - 1);
 
    if (::ioctl(fd, SIOCGARP, &req) < 0)
        return Error::make(Status::ArpResolveFail, ::strerror(errno));
 
    // ATF_COM: entry is complete and MAC is valid.
    // entries without ATF_COM exist but have no resolved MAC yet.
    if (!(req.arp_flags & ATF_COM))
        return Error::make(Status::ArpResolveFail,
                           "arp_lookup: entry incomplete (ATF_COM not set)");
 
    __builtin_memcpy(out_mac, req.arp_ha.sa_data, 6);
    return Error::none();
}

//  randomize_mac()
//  generates a random locally-administered unicast MAC from /dev/urandom.
//  never fails — falls back to stack-address xor if urandom unavailable.
//  returns Error::none() always, signature kept uniform for consistency.

[[nodiscard]] inline Error randomize_mac(uint8_t out_mac[6]) noexcept
{
    int urfd = ::open("/dev/urandom", O_RDONLY);
    if (urfd >= 0) {
        ::read(urfd, out_mac, 6);
        ::close(urfd);
    } else {
        uintptr_t seed = reinterpret_cast<uintptr_t>(out_mac);
        for (int i = 0; i < 6; ++i) {
            seed ^= (seed >> 13) ^ (seed << 7);
            out_mac[i] = static_cast<uint8_t>(seed & 0xff);
        }
    }
    out_mac[0] &= 0xFE;   // bit 0 = 0 → unicast
    out_mac[0] |= 0x02;   // bit 1 = 1 → locally administered
    return Error::none();
}

//  raw_send()
//  the single sendto() call in the library.
//  dst_mac[6] fills sll_addr — must be resolved before calling.

[[nodiscard]] inline Error raw_send(int            fd,
                                     int            ifindex,
                                     const uint8_t* buf,
                                     uint32_t       len,
                                     const uint8_t  dst_mac[6]) noexcept
{
    ::sockaddr_ll sll{};
    sll.sll_family   = AF_PACKET;
    sll.sll_ifindex  = ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_halen    = 6;
    __builtin_memcpy(sll.sll_addr, dst_mac, 6);

    ssize_t sent = ::sendto(fd, buf, len, 0,
                             reinterpret_cast<const ::sockaddr*>(&sll),
                             sizeof(sll));
    if (sent < 0)
        return Error::make(Status::SendFail, ::strerror(errno));

    if (static_cast<uint32_t>(sent) < len)
        return Error::make(Status::SendTruncated,
                           "sendto() sent fewer bytes than requested");

    return Error::none();
}

//  raw_recv()
//  single recvfrom() call — reads one frame into buf[0..cap].
//
//  return convention (three distinct outcomes):
//    n  > 0  — frame received, n bytes written into buf
//    n == 0  — timeout (EAGAIN / EINTR) — not an error, check stop flag
//    n == -1 — hard error, err is populated
//
//  out_src_mac is filled from sockaddr_ll — may be null if not needed.

[[nodiscard]] inline int32_t raw_recv(int      fd,
                                       uint8_t* buf,
                                       uint32_t cap,
                                       uint8_t  out_src_mac[6],
                                       Error&   err) noexcept
{
    ::sockaddr_ll sll{};
    ::socklen_t   sll_len = sizeof(sll);

    ssize_t n = ::recvfrom(fd, buf, cap, 0,
                            reinterpret_cast<::sockaddr*>(&sll),
                            &sll_len);
    if (n < 0) {
        if (errno == EAGAIN || errno == EINTR)
            return 0;
        err = Error::make(Status::RecvFail, ::strerror(errno));
        return -1;
    }

    if (out_src_mac)
        __builtin_memcpy(out_src_mac, sll.sll_addr, 6);

    return static_cast<int32_t>(n);
}

//  close_fd()
//  closes fd and resets it to INVALID_FD. safe to call multiple times.

inline void close_fd(int& fd) noexcept
{
    if (fd != INVALID_FD) {
        ::close(fd);
        fd = INVALID_FD;
    }
}

} // namespace lynx::sock

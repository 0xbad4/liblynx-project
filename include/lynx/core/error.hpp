#pragma once

//  error codes for the entire library.
//  one flat enum — no per-class error namespaces, errors compose cleanly
//  across layers (Interface, Packet, Protocol, Buffer).

#include <cstdint>

namespace lynx {

enum class Status : uint8_t {

    // ── ok
    Ok                  = 0,    // no error

    // ── socket errors
    SocketCreateFail    = 1,    // socket(AF_PACKET) returned -1
    SocketBindFail      = 2,    // bind() to interface failed
    SocketOptionFail    = 3,    // setsockopt() failed (promisc, timeout, etc.)

    // ── interface errors
    IfaceNotFound       = 10,   // if_nametoindex() could not resolve name
    IfaceNotOpen        = 11,   // send/recv called before open()
    IfaceAlreadyOpen    = 12,   // open() called twice without close()

    // ── MAC / ARP resolution errors
    MacResolveFail      = 20,   // SIOCGIFHWADDR ioctl failed
    ArpResolveFail      = 21,   // SIOCGARP lookup failed — host not in cache
    ArpTimeout          = 22,   // reserved: active ARP probe timed out (v1)

    // ── send errors
    SendFail            = 30,   // sendto() returned -1
    SendTruncated       = 31,   // sendto() sent fewer bytes than requested

    // ── recv errors
    RecvFail            = 40,   // recvfrom() returned -1 (not EAGAIN/EINTR)

    // ── buffer errors
    BufferTooSmall      = 50,   // write would exceed Buffer::cap
    BufferAllocFail     = 51,   // new uint8_t[] threw / returned null

    // ── packet / dissection errors
    MalformedPacket     = 60,   // raw bytes too short for declared header
    UnknownProtocol     = 61,   // ethertype / IP proto not in registry
    TruncatedPayload    = 62,   // payload length field exceeds buffer bounds
    ChecksumMismatch    = 63,   // received checksum does not match computed

    // ── serialization errors
    SerializeFail       = 70,   // layer serialize() could not write to Buffer
    MissingLayer        = 71,   // required lower layer absent (e.g. no IPv4
                                //   when computing TCP pseudo-header)

    // ── generic
    InvalidArgument     = 90,   // null pointer, zero length, bad enum value
    NotImplemented      = 91,   // stub — feature not built in this version
    Unknown             = 99,   // catch-all, should never appear in practice
};

//  status_str()
//  returns a short static string for a Status value.
//  safe to call from signal handlers — no allocation, no syscalls.

[[nodiscard]] inline const char* status_str(Status s) noexcept {
    switch (s) {
        case Status::Ok:                return "ok";
        case Status::SocketCreateFail:  return "socket create failed";
        case Status::SocketBindFail:    return "socket bind failed";
        case Status::SocketOptionFail:  return "socket option failed";
        case Status::IfaceNotFound:     return "interface not found";
        case Status::IfaceNotOpen:      return "interface not open";
        case Status::IfaceAlreadyOpen:  return "interface already open";
        case Status::MacResolveFail:    return "MAC resolve failed";
        case Status::ArpResolveFail:    return "ARP lookup failed";
        case Status::ArpTimeout:        return "ARP timeout";
        case Status::SendFail:          return "send failed";
        case Status::SendTruncated:     return "send truncated";
        case Status::RecvFail:          return "recv failed";
        case Status::BufferTooSmall:    return "buffer too small";
        case Status::BufferAllocFail:   return "buffer alloc failed";
        case Status::MalformedPacket:   return "malformed packet";
        case Status::UnknownProtocol:   return "unknown protocol";
        case Status::TruncatedPayload:  return "truncated payload";
        case Status::ChecksumMismatch:  return "checksum mismatch";
        case Status::SerializeFail:     return "serialize failed";
        case Status::MissingLayer:      return "missing required layer";
        case Status::InvalidArgument:   return "invalid argument";
        case Status::NotImplemented:    return "not implemented";
        default:                        return "unknown error";
    }
}

//  Error
//
//  a plain {type, msg} value passed by the socket helpers in socket.hpp.
//  stateless — just a carrier, no methods beyond construction.
//
//  usage:
//      Error e;
//      if (!some_fn(..., e)) {
//          // e.type  → Status::SocketBindFail
//          // e.msg   → "bind() failed: ..."
//      }

struct Error {
    Status      type = Status::Ok;
    const char* msg  = nullptr;     // static string — never freed

    // true when no error is recorded
    [[nodiscard]] bool ok()    const noexcept { return type == Status::Ok; }

    // human-readable: prefers the specific msg, falls back to status_str()
    [[nodiscard]] const char* what() const noexcept {
        if (msg  && msg[0] != '\0') return msg;
        return status_str(type);
    }

    // factory helpers — keep call sites readable
    [[nodiscard]] static Error make(Status s, const char* m) noexcept {
        return { s, m };
    }

    [[nodiscard]] static Error none() noexcept {
        return { Status::Ok, nullptr };
    }

    void clear() noexcept {
        type = Status::Ok;
        msg  = nullptr;
    }
};

} // namespace lynx

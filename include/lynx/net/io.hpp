#pragma once

#if defined(__linux__)
    #include "lynx/net/platform/linux/iface.hpp"
    #include "lynx/net/platform/linux/socket.hpp"
#else
    #error "lynx::io is only supported on Linux for now"

#endif

#pragma once

#if defined(__linux__)
    #include "./platform/linux/iface.hpp"
    #include "./platform/linux/socket.hpp"
#else
    #error "lynx::io is only supported on Linux for now"

#endif

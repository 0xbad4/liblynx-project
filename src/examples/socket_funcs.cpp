

/*
C++ 17 or higher version required (for std::span)

$ g++ -std=c++23 socket_funcs.cpp -o sock_fun
$ sudo ./sock_fun  # root privs required
*/

#include <lynx/lynx>
#include <iostream>
#include <cstring>

using namespace lynx;


int main() {
    // 1. resolve interface index
    int ifindex = 0;
    Error err = sock::resolve_ifindex("wlan0", ifindex);

    if (!err.ok()) {
        std::cerr << "resolve_ifindex failed: " << err.what() << "\n";
        return 1;
    }

    std::cout << "ifindex: " << ifindex << "\n";

    // 2. open raw socket
    int fd;
    err = sock::open_raw(fd);

    if (!err.ok()) {
        std::cerr << "open_raw failed: " << err.what() << "\n";
        close(fd);
        return 1;
    }

    // 3. get interface MAC
    uint8_t iface_mac[6];
    err = sock::get_iface_mac(fd, "wlan0", iface_mac);
    if (!err.ok()) {
        std::cerr << "get_iface_mac failed: " << err.what() << "\n";
        close(fd);
        return 1;
    }

    auto iface_mac_encoded = lynx::utils::mac_encode(iface_mac);

    std::cout << "iface MAC: " << iface_mac_encoded.data << "\n";

    // 4. random MAC
    uint8_t rnd_mac[6];
    lynx::utils::buf_randomize(rnd_mac, 6);

    auto rnd_mac_encoded = lynx::utils::mac_encode(rnd_mac);

    std::cout << "random MAC: " << rnd_mac_encoded.data << "\n";

    // 5. ARP lookup
    uint8_t target_ip[4] = {100, 112, 0, 1};
    uint8_t target_mac[6];

    err = sock::arp_lookup(fd, "wlan0", target_ip, target_mac);

    if (!err.ok()) {
        std::cerr << "arp_lookup failed: " << err.what() << "\n";
        close(fd);
        return 1;
    }

    auto ip_encoded = lynx::utils::ipv4_encode(target_ip);
    auto target_mac_encoded = lynx::utils::mac_encode(target_mac);

    std::cout << ip_encoded.data << " is at " << target_mac_encoded.data << "\n";


    return 0;
}

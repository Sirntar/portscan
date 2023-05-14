/**
 * PortScanner.h
 * 
 *  Copyright (c) 2023, Tymoteusz Wenerski. All rights reserved.
 * 
 *  Use of this source code is governed by a MIT license
 *  that can be found in the License file.
*/

#ifndef PORTSCAN_PORTSCANNER_H
#define PORTSCAN_PORTSCANNER_H

#include "../net/SubNet.h"
#include "../net/ServicesDictionary.h"
#include "../async/ThreadPool.h"

#include <ctime>
#include <chrono>
#include <mutex>

#ifndef _WIN32 // POSIX (a small standarizations)
#   define SOCKET int32_t
#   define NO_ERROR 0
#   define SD_RECEIVE SHUT_RD
#   define INVALID_SOCKET -1
#   define SOCKET_ERROR ~(0)
#   define closesocket(s) close(s)
#   define ioctlsocket(s, v, b) ioctl(s, v, b)
#endif

#define PACKET_SIZE 2048 // size of buffers for UDP packets

namespace scanner {
    using namespace net;
    using namespace async;

    typedef uint16_t port;

    struct portRange{
        port from = 0;
        port to = 65535;
    };

    struct _flags {
        bool b_threads = true;
        CONNECTION_TYPE ct_protocol = ALL;
        timeval t_timeout = {0, 500000};
        struct portRange pr_range{};
        int i_thread_count = std::thread::hardware_concurrency();
        bool b_each_in_new_thread = false;
    };
    typedef _flags flags;

    class PortScanner : public SubNet {
    private:
        flags settings{};
        std::mutex print_mutex;

        ServicesDictionary* service_dictionary = nullptr;

        void init_dictionary();

        void print(const std::ostringstream& stream);
        void print(const std::string& string);
        void print_settings();
        void print_scan_info(const IpAddress& address);
        void print_row(port port, bool status, CONNECTION_TYPE protocol);
        void print_separator(const char& separator);

        void check_port(IpAddress ip, port port);

        bool test_port(IpAddress ip, port in_port, CONNECTION_TYPE protocol, timeval timeout);
    public:
        PortScanner(IpAddress* ip, IpAddress* mask, flags args);
        PortScanner(std::string& ip, std::string& mask, flags args);

        ~PortScanner() { delete service_dictionary; }

        void setFlags(flags f) { this->settings = f; }
        void scan();
        void no_threads_scan();
        void crazy_scan();

        static bool tcp_connect(IpAddress ip, port in_port, timeval timeout);
        static bool udp_connect(IpAddress ip, port in_port, timeval timeout);
    };
}

#endif //PORTSCAN_PORTSCANNER_H

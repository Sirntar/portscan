/**
 * Print.cc
 * 
 *  Copyright (c) 2023, Tymoteusz Wenerski. All rights reserved.
 * 
 *  Use of this source code is governed by a MIT license
 *  that can be found in the License file.
*/

#include "PortScanner.h"

#include <iostream>
#include <iomanip>

namespace scanner {

    void PortScanner::print(const std::ostringstream &stream) {
        std::lock_guard<std::mutex> lock(print_mutex);
        std::cout << stream.str();
    }

    void PortScanner::print(const std::string &string) {
        std::lock_guard<std::mutex> lock(print_mutex);
        std::cout << string;
    }

    void PortScanner::init_dictionary() {
        std::cout << "Loading services dictionary...\n";
        this->service_dictionary = new ServicesDictionary();
    }

    void PortScanner::print_settings() {
        std::ostringstream ss;

        ss  << std::endl << "SETTINGS:\n"
            << "\tSubnet ip: " << this->getSubnetAddress().getAsString() << std::endl
            << "\tBroadcast ip: " << this->getBroadcastAddress().getAsString() << std::endl
            << "\tPorts for scan: " << this->settings.pr_range.from << " - " << this->settings.pr_range.to << std::endl
            << "\tProtocols: " << (this->settings.ct_protocol == TCP ? "TCP" : this->settings.ct_protocol == UDP ? "UDP" : "TCP and UDP") << std::endl
            << "\tTime for response [only for TCP/IP!]: "
            << (static_cast<double>(this->settings.t_timeout.tv_sec) +
                static_cast<double>(this->settings.t_timeout.tv_usec) * 0.000001)
            << "s\n"
            << "\tMultitasking: " << (this->settings.b_threads ? "true" : "false") << std::endl
            << "\tThread pool: " << this->settings.i_thread_count << std::endl
            << std::setfill('-') << std::setw(56) << "" << std::setfill(' ') << std::endl;

        print(ss);
    }

    void PortScanner::print_scan_info(const IpAddress& address) {
        std::ostringstream ss;

        ss  << "\nStarting scanning for " << address.getAsString()
            << " with timeout = "
            << (static_cast<double>(this->settings.t_timeout.tv_sec) +
                static_cast<double>(this->settings.t_timeout.tv_usec) * 0.000001)
            << "s\n"
            << std::setw(56) << std::setfill('=') << "" << std::setfill(' ') << std::endl
            << std::left << std::setw(20) << "PORT/PROTOCOL"
            << std::setw(20) << "STATUS"
            << std::setw(20) << "SERVICE"
            << std::endl;

        print(ss);
    }

    void PortScanner::print_row(port port, bool status, CONNECTION_TYPE protocol) {
        std::string serv = "unknown";

        if (status) {
            if (service_dictionary != nullptr) {
                serv = service_dictionary->getService(port, protocol);
            }

            std::ostringstream ss;
            ss
                << std::left << std::setw(20) << std::to_string(port) + (protocol == TCP ? "/tcp" : "/udp")
                << std::left << std::setw(20) << (protocol == TCP ? "open" : "open|filtered") 
                << std::left << serv << std::endl;
            print(ss);
        }
    }

    void PortScanner::print_separator(const char &separator) {
        std::ostringstream ss;

        ss << std::setw(56) << std::setfill(separator) << "" << std::setfill(' ') << std::endl;

        print(ss);
    }
}
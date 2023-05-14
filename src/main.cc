/**
 * protscan
 * 
 *  Copyright (c) 2023, Tymoteusz Wenerski. All rights reserved.
 * 
 *  Use of this source code is governed by a MIT license
 *  that can be found in the License file.
*/

#define VER "v2.0.0"

#include <iostream>
#include <string>
#include <iomanip>
#include <locale>

#include "scanner/PortScanner.h"

using std::cout;
using std::string;
using scanner::flags;

bool is_number(const std::string& s) {
    for (auto c : s)
        if (!std::isdigit(c)) return false;
    return true;
}

void print_version() {
    cout
        << std::setfill('-') << std::setw(56) << "" << std::setfill(' ') << std::endl
        << std::setw(50) << "portscan " VER " [build: " __DATE__ " "  __TIME__ "]" << std::endl
        << std::setw(38) << std::right << "by Tymoteusz Wenerski" << std::endl
        << std::setfill('-') << std::setw(56) << "" << std::setfill(' ') << std::endl;
}

void print_help() {
    cout 
        << std::endl 
        << std::setw(56) << "usage: portscan <Ip address> <Ip mask> [-t <timeout in ms>]" << std::endl
        << std::setw(46) << "[-f | --fast] [-p <from> <to>]" << std::endl
        << std::setw(50) << "[-TCP] [-UDP] [-ALL] [-h | --help]" << std::endl
        << std::setw(46) << "[-th <threads>] [--no-threads]" << std::endl
        << std::setw(25) << "[--crazy]" << std::endl << std::endl
        << "--crazy\n\tFor every request create a new thread.\n"
        << "\tNot recommended, but it's really fast.\n" 
        << "\tAnyway, you should probably set timeout to 5-10s,\n\t because the function is to fast"
        << std::endl;
}

void get_ip_addr(char** argv, int i, string& s_ip, string& s_mask) {
    unsigned long long ull_tmp;

    if (s_ip.empty()){
        s_mask = argv[i];
        ull_tmp = s_mask.find('/');

        if (ull_tmp != std::string::npos) {
            s_ip = s_mask.substr(0, ull_tmp);
            s_mask = s_mask.substr(ull_tmp, s_mask.length());
        } else {
            s_ip = s_mask;
            s_mask.clear();
        }
    } else if(s_mask.empty()) {
        s_mask = argv[i];
    }
}

void get_port_range(char** argv, int i, scanner::port& from, scanner::port& to) {
    long l_tmp = std::strtol(argv[i + 1], nullptr, 10);
    long l_tmp2 = std::strtol(argv[i + 2], nullptr, 10);

    if ((l_tmp >= 0 && l_tmp2 >= 0) && (l_tmp <= 65535 && l_tmp2 <= 65535)) {
        if (l_tmp <= l_tmp2) {
            from = static_cast<scanner::port>(l_tmp);
            to = static_cast<scanner::port>(l_tmp2);
        } else {
            from = static_cast<scanner::port>(l_tmp2);
            to = static_cast<scanner::port>(l_tmp);
        }
    }
}

void get_timeout(char** argv, int i, timeval& timeout) {
    long l_tmp = static_cast<long>(std::strtol(argv[i + 1], nullptr, 10));
    long l_tmp2 = l_tmp / 1000;
    l_tmp -= l_tmp2 * 1000;

    if(l_tmp2 > 0)
        timeout.tv_sec = l_tmp2;
    else
        timeout.tv_sec = 0;
    timeout.tv_usec = l_tmp * 1000;
}

int main(int argc, char** argv) {
    scanner::flags f{};

    string s_ip{}, s_mask{};
    std::locale loc{};

    auto* str_tmp = new string;

    scanner::PortScanner* portScanner = nullptr;

    print_version();

    cout << "Reading args...\n";

    bool help_flag = false;
    for(int i = 1; i < argc; i++) {
        if (argv[i][0] != '-' && !isalpha(argv[i][0])) {
            get_ip_addr(argv, i, s_ip, s_mask);
        } else {
            *str_tmp = argv[i];

            if((*str_tmp)[0] == '-')
                *str_tmp = str_tmp->substr(1, str_tmp->length());

            for(auto& c : *str_tmp)
                c = std::tolower(c,loc);

            if (*str_tmp == "h" || *str_tmp == "-help") {
                print_help();
                i = argc; // skip rest
                help_flag = true; // skip scanning
            } else if (*str_tmp == "s" || *str_tmp == "-fast") {
                f.pr_range = {0, 10000};
            } else if (*str_tmp == "tcp") {
                f.ct_protocol = scanner::net::TCP;
            } else if (*str_tmp == "udp") {
                f.ct_protocol = scanner::net::UDP;
            } else if (*str_tmp == "all") {
                f.ct_protocol = scanner::net::ALL;
            } else if (*str_tmp == "p") {
                if (i + 2 < argc) {
                    if (is_number(argv[i + 1]) && is_number(argv[i + 2])) {
                        get_port_range(argv, i, f.pr_range.from, f.pr_range.to);
                        i += 2;
                    }
                }
            } else if (*str_tmp == "-no-threads") {
                f.b_threads = false;
                f.i_thread_count = 1;
            } else if (*str_tmp == "t") {
                if (i + 1 < argc) {
                    if (is_number(*(argv + i + 1))) {
                        get_timeout(argv, i, f.t_timeout);
                    }
                }
            } else if (*str_tmp == "th") {
                if(i + 1 < argc) {
                    if (is_number(*(argv + i + 1))) {
                        long l_tmp = static_cast<long>(std::strtol(argv[i + 1], nullptr, 10));

                        if (l_tmp > 0) {
                            f.i_thread_count = l_tmp;
                        }
                    }
                }
            } else if (*str_tmp == "-crazy") {
                f.b_each_in_new_thread = true;
            } else {
                std::cerr << "WARNING: Useless argument `" << argv[i] << "`\n";
            }
        }
    }

    delete str_tmp;

    if (help_flag) {
        return 0;
    }

    if(!s_ip.empty() && !s_mask.empty()) {
        try {
            portScanner = new scanner::PortScanner(s_ip, s_mask, f);
            if (f.b_threads) {
                portScanner->scan();
            } else if (f.b_threads) {
                portScanner->no_threads_scan();
            } else {
                portScanner->crazy_scan();
            }
        } catch (const std::exception& e) {
            std::cerr << e.what() << std::endl;
        }
    } else {
        std::cerr << "ERROR: missing IP or MASK parameter..\n";
    }

    delete portScanner;
    return 0;
}
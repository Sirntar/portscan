/**
 * PortScanner.cc
 * 
 *  Copyright (c) 2023, Tymoteusz Wenerski. All rights reserved.
 * 
 *  Use of this source code is governed by a MIT license
 *  that can be found in the License file.
*/

#include "PortScanner.h"

#include <iostream>
#include <thread>
#include <vector>
#include <system_error>

namespace scanner {
    bool PortScanner::test_port(IpAddress ip, port in_port, CONNECTION_TYPE protocol, timeval timeout) {
        return protocol == TCP ? PortScanner::tcp_connect(ip, in_port, timeout) : PortScanner::udp_connect(ip, in_port, timeout);
    }

    PortScanner::PortScanner(IpAddress *ip, IpAddress *mask, flags args) 
            : SubNet(ip, mask), settings(args) {
        init_dictionary();
        print_settings();
    }

    PortScanner::PortScanner(std::string &ip, std::string &mask, flags args)             
            : SubNet(ip, mask), settings(args) {
        init_dictionary();
        print_settings();
    }

    void PortScanner::scan() {
        if (this->settings.b_threads) {
            return no_threads_scan();
        } else if (this->settings.b_each_in_new_thread) {
            return crazy_scan();
        }

        auto thread_pool = std::unique_ptr<ThreadPool>(new ThreadPool(settings.i_thread_count));
        auto current_ip = IpAddress(this->getSubnetAddress());
        auto broadcast_ip = IpAddress(this->getBroadcastAddress());

        port port = 0;
        while (current_ip <= this->getBroadcastAddress()) {
            print_scan_info(current_ip);

            port = settings.pr_range.from;
            do {
                scanner::port p = port;
                thread_pool->push(
                    [this, current_ip, p]() {
                        check_port(current_ip, p);
                    }
                );
                port++;
            } while(port != 0 && port <= this->settings.pr_range.to);

            thread_pool->waitForThreads();
            current_ip.operator++();
            print_separator('=');
        }
    }

    void PortScanner::no_threads_scan() {
        if (this->settings.b_each_in_new_thread) {
            return crazy_scan();
        }

        auto current_ip = IpAddress(this->getSubnetAddress());
        auto broadcast_ip = IpAddress(this->getBroadcastAddress());

        port port = 0;
        while (current_ip <= this->getBroadcastAddress()) {
            print_scan_info(current_ip);

            port = settings.pr_range.from;
            do {
                scanner::port p = port;
                check_port(current_ip, p); // no threads allowed
                port++;
            } while(port != 0 && port <= this->settings.pr_range.to);

            current_ip.operator++();
            print_separator('=');
        }
    }

    /**
     * This function is legacy code from the first version of the program.
     * It is very fast, but it violates multiple rules of good multi-threaded programming.
     * 
     * Before we proceed, let's discuss why this function works.
     * In every modern operating system, there is a Task/Process Manager that manages
     * all tasks and processes in the system. This means that there will be interruptions
     * in the execution of processes or threads to allow each task to have some CPU time.
     * What if we create 1,000 or 10,000 threads? Each of them will receive some CPU time,
     * more than they would get if there were only six threads.
     * 
     * However, it is important to note that this is considered a bad practice, but for the sake of demonstration,
     * it has been marked as legacy code.
     * 
     * You have been warned, so let's proceed!
     */
    void PortScanner::crazy_scan() {
        auto current_ip = IpAddress(this->getSubnetAddress());
        auto broadcast_ip = IpAddress(this->getBroadcastAddress());
        std::vector<std::thread*> threads;

        port port = 0;
        while (current_ip <= this->getBroadcastAddress()) {
            print_scan_info(current_ip);

            port = settings.pr_range.from;
            do {
                scanner::port p = port;

                int tries = 0;
                // Fasten your seat belt, because it's gonna be a crazy drive!!!

                /**
                 * In "Clean Code" by Robert C. Martin [page 48],
                 * it is stated that using 'goto' is generally considered
                 * bad practice acording to Dijkstra rules.
                 * Well.. Dijkstra also said, that functions should have only
                 * one entry and one exit. That rule was extended by Martin
                 * to the point at which loops shouldn't have any break or continue,
                 * which - in some cases - is almost impossible to avoid.
                 *
                 * So let's sum up Dijkstra and Martin rules:
                 * Goto is considered bad practice, 
                 * because it often leads to uncontrolled jumps
                 * and makes code harder to read and maintain.
                 *
                 * However, in certain cases, if used judiciously and in a
                 * well-structured manner, it can potentially provide huge optimizations.
                */  
            try_new_thread:
                try {
                    threads.push_back( 
                        new std::thread(
                            [this, current_ip, p]() {
                                check_port(current_ip, p);
                            }
                        )
                    );
                } catch (const std::system_error& e) {
                    // Owww... system couldn't handle
                    // need some space
                    for (auto &thread : threads) {
                        thread->join();
                        delete thread;
                    }
                    threads.clear();
                    if (tries++ > 10) {
                    std::cerr << "Threads are messed up" << std::endl;
                    exit(666);
                    }
                    goto try_new_thread;
                }
                port++;
            } while(port != 0 && port <= this->settings.pr_range.to);

            for (auto &thread : threads) {
                thread->join();
                delete thread;
            }
            threads.clear();
            current_ip.operator++();
            print_separator('=');
        }
    }

    void PortScanner::check_port(IpAddress ip, port port) {
        bool is_open = false;

        if (settings.ct_protocol != ALL) {
            is_open = test_port(ip, port, settings.ct_protocol, settings.t_timeout);
            print_row(port, is_open, settings.ct_protocol);
        } else {
            is_open = test_port(ip, port, TCP, settings.t_timeout);
            print_row(port, is_open, TCP);
            is_open = test_port(ip, port, UDP, settings.t_timeout);
            print_row(port, is_open, UDP);
        }
    }
}
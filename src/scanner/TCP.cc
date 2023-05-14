/**
 * TCP.cc
 * 
 *  Copyright (c) 2023, Tymoteusz Wenerski. All rights reserved.
 * 
 *  Use of this source code is governed by a MIT license
 *  that can be found in the License file.
*/

#include "PortScanner.h"
#include <iostream>

namespace scanner {

    bool PortScanner::tcp_connect(IpAddress ip, port in_port, timeval timeout) {
        struct sockaddr_in addr{0}; // connection struct
        SOCKET S_socket = 1;
        int res = 0;
        u_long u_mode = 1;
        fd_set fd{}; // struct needed for selecting socket

        // for socket state purposes
        int val = 0;
        socklen_t len = 0;

#ifdef _WIN32
        // Windows needs to enable socket before using it.
        WSADATA wsaData{0};

        if (WSAStartup(MAKEWORD(2,2), &wsaData) != NO_ERROR) {
            std::cerr << "ERROR: WSAStartup error... Ask Bill Gates for help..." << WSAGetLastError() << std::endl;
            WSACleanup();
        }
#endif

        // Create TCP socket. Many people skip last parameter,
        // but accordint to standard it should be here.
        S_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

       if (S_socket == INVALID_SOCKET) {
            std::cerr << "ERROR: Cannot create socket.." << std::endl;
#ifdef _WIN32
            WSACleanup();
#endif
            closesocket(S_socket);
            return false;
        }

        // fill conection struct
        addr.sin_addr.s_addr = ip.getAsAddr().num;
        addr.sin_port = htons(in_port);
        addr.sin_family = AF_INET; // ipv4

        // set socket as non-blocking
        res = ioctlsocket(S_socket, FIONBIO, &u_mode);
        if (res == SOCKET_ERROR) {
            std::cerr << " WARNING: Cannot set socket as non-blocking..." << std::endl;
        }


        // In TCP/IP it is enough to check whether the port is available.
        res = connect(S_socket, (struct sockaddr*)&addr, sizeof(addr));

        // If response wasn't immediately received,
        // we have to wait a little bit
        if (res < 0) {
            FD_ZERO(&fd);
            FD_SET(S_socket, &fd);

            // set timeout for connection
            res = select(static_cast<int32_t>(S_socket) + 1, nullptr, &fd, nullptr, &timeout);

            if (res > 0) { // setting timeout failed
                val = 0;
                len = sizeof(int);

                // get server response or end - if there is no response -> port is not available
                res = getsockopt(S_socket, SOL_SOCKET, SO_ERROR, (char*)(&val), &len);

                // if response exist, but the response is "FALSE" -> port is not available
                if (res == SOCKET_ERROR || val) {
                    res = SOCKET_ERROR;
                }
            } else {
                res = SOCKET_ERROR;
            }
        }

        shutdown(S_socket, SD_RECEIVE); // block socket from reciving requests
        closesocket(S_socket); // close socket

        if (res == SOCKET_ERROR) {
#ifdef _WIN32
            WSACleanup();
#endif
            return false; // closed
        } else {
            return true; // opened
        }
    }
    
}
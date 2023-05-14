/**
 * UDP.cc
 * 
 *  Copyright (c) 2023, Tymoteusz Wenerski. All rights reserved.
 * 
 *  Use of this source code is governed by a MIT license
 *  that can be found in the License file.
 * 
 * UDP sockets require administrator privileges to connect to the server.
 * At least on Windows.
*/

#include "PortScanner.h"
#include <iostream>

namespace scanner {

    struct ipHeader {
        // there is possility of default initialization of bit fields, but it requires C++20 standard,
        // so we have to remember to initialize the bit fields manually (with zeros)
#if __BYTE_ORDER == __LITTLE_ENDIAN
        uint8_t ihl:4;
        uint8_t version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
        uint8_t version:4;
        uint8_t ihl:4;
#endif
        uint8_t tos = 16; // small delay
        uint16_t len = 0; // pkg size
        uint16_t id = htons(54321);
        uint16_t flag_off = 0;
        uint8_t ttl = 64; // time to live
        uint8_t protocol = 17; // UDP (diagram protocol)
        uint16_t checksum = 0;
        uint32_t sourceIp = 0;
        uint32_t destination = 0;
    };

    struct udpHeader {
        uint16_t sourcePort = 0;
        uint16_t destinationPort = 0;
        uint16_t len = 0;
        uint16_t checksum = 0;
    };

    struct icmpHeader {
        uint8_t type; // msg type
        uint8_t code;
        uint16_t checksum;
        // based on linux kernel implementation:
        union {
            struct {
                uint16_t id;
                uint16_t sequence;
            } echo;
            uint32_t gateway;
            struct {
                uint16_t unused;
                uint16_t mtu;
            } frag;
        } unused;
    };

    // RFC checksum algorithm
    unsigned short calcCheckSum(uint16_t *addr, int_fast32_t count) {
        uint32_t sum = 0;

        for(; count > 0; count--)
            sum += *addr++;

        sum = (sum >> 16) + (sum & 0xffff);
        sum += (sum >> 16);

        return (unsigned short)(~sum);
    }

    bool PortScanner::udp_connect(IpAddress ip, port in_port, timeval timeout) {
        struct sockaddr_in addr{0}; // connection struct
    #ifndef WIN32
        unsigned int i_addrSize = sizeof(addr);
    #else
        int i_addrSize = sizeof(addr);
    #endif

        char buff[PACKET_SIZE] = {0}; // pkg to send request
        char rcBuff[PACKET_SIZE] = {0}; // ppkg to receive response
        struct ipHeader *iph = (struct ipHeader *)buff, *rcIph = nullptr;
        struct udpHeader *udh = (struct udpHeader *)(buff + sizeof(ipHeader)), *rcUdh = nullptr;
        struct icmpHeader *rcIch = nullptr;

        SOCKET S_socket = 1;
        long res = 0;
        bool reply_flag = false;
        bool close_flag = false;

        u_long u_mode = 1;
        fd_set fd{}; // struct needed for selecting socket
        timeval udpTimeout = {1, 0}; // time to speed up socket connection

    #ifdef _WIN32
        // Windows needs to enable socket before using it.
        WSADATA wsaData{0};

        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != NO_ERROR) {
            std::cerr << "ERROR: WSAStartup error... Ask Bill Gates for help..." << WSAGetLastError() << std::endl;
            WSACleanup();
        }
    #endif

        // I'm using lower network layer, because I just want to send header
        // to trick UDP protocol, but it may require root privileges. 
        S_socket = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);

        if (S_socket == INVALID_SOCKET) {
            std::cerr << "ERROR: Cannot create UDP sockets.." << std::endl;
    #ifdef _WIN32
            WSACleanup();
    #endif
            closesocket(S_socket);
            return false;
        }

        addr.sin_addr.s_addr = ip.getAsAddr().num;
        addr.sin_port = htons(in_port);
        addr.sin_family = AF_INET; // ipv4

        // header to send:
        iph->version = 4; // 0100 0101
        iph->ihl = 5;
        iph->tos = 16; // short interval
        iph->len = sizeof(struct ipHeader) + sizeof(udpHeader); // pkg size (it's only header in my case)
        iph->id = htons(54321);
        iph->flag_off = 0;
        iph->ttl = 255; // time to live
        iph->protocol = IPPROTO_UDP; // UDP (diagram protocol)
        iph->sourceIp = 666; // let's fake ip - It's an attack anyway
        iph->destination = ip.getAsNetNumber();
        iph->checksum = calcCheckSum((unsigned short *)buff, sizeof(struct ipHeader) + sizeof(struct udpHeader));
        // extend header for UDP
        udh->sourcePort = htons(9); // port doesn't matter
        udh->destinationPort = htons(in_port);
        udh->len = htons(sizeof(struct udpHeader));
        udh->checksum = 0; // optional field if anyone care about data integrity

        // ok, so the idea is as follow:
        // 1. send a few messages
        // 2. wait for response
        // 3. no response = open or close
        // 4. if UDP will answer with the same address, on which I've send pkg = the port is open
        for(int i = 0; i < 5; i++) { // czas wykonywania min = 5s
            res = sendto(S_socket, buff, iph->len, 0, (struct sockaddr *) &addr, i_addrSize); // return number of bites or SOCKET_ERROR

            if(res == SOCKET_ERROR)
                break;

            FD_ZERO(&fd);
            FD_SET(S_socket, &fd);

            while(select(S_socket + 1, &fd, nullptr, nullptr, &udpTimeout) > 0) {
                if(recvfrom(S_socket, rcBuff, PACKET_SIZE, 0, (struct sockaddr *) &addr, &i_addrSize) > 0) {
                    rcIph = (struct ipHeader*) rcBuff;
                    rcUdh = (struct udpHeader*)(rcBuff + sizeof(struct ipHeader));
                    rcIch = (struct icmpHeader*)(rcBuff + sizeof(struct ipHeader));

                    reply_flag = true;

                    rcIph->sourceIp = htonl(rcIph->sourceIp);

                    if(rcIph->protocol == IPPROTO_UDP) {
                        if(rcIph->sourceIp == iph->destination) { // port might be open or closed
                            i = 10;
                            close_flag = false;
                            break;
                        } else if(rcUdh->sourcePort == udh->sourcePort && rcIch->type == 0) { // redirection to local net?
                            // port is open of course
                            i = 10;
                            close_flag = false;
                            break;
                        }
                    }
                }
            }
        }
        shutdown(S_socket, SD_RECEIVE);
        closesocket(S_socket);

        // now we have to check for ICMP response
        // if there is any - the port is closed
        S_socket = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
        if(S_socket == SOCKET_ERROR) {
            std::cerr << "ERROR: Cannot create ICMP socket.." << std::endl;
    #ifdef _WIN32
            WSACleanup();
    #endif
            closesocket(S_socket);
            return false;
        }

        // inform socket, that we are providing ip header
    #ifndef WIN32
        res = setsockopt(S_socket, IPPROTO_IP, IP_HDRINCL, &u_mode, sizeof(u_mode));
    #else
        res = setsockopt(S_socket, IPPROTO_IP, IP_HDRINCL, (const char*)(&u_mode), sizeof(u_mode));
    #endif
        if(res == SOCKET_ERROR) {
            std::cerr << "WARNING: Cannot set IP_HDRINCL..." << std::endl;
        }

        for(int i = 0; i < 3; i++) {
            if (sendto(S_socket, buff, iph->len, 0, (struct sockaddr *) &addr, i_addrSize) > 0) {

                // extend time limit, becouse eg. linux (kernel) slower response for about 1s
                udpTimeout = {2, 0};
                FD_ZERO(&fd);
                FD_SET(S_socket, &fd);

                if (select(S_socket + 1, &fd, nullptr, nullptr, &udpTimeout) > 0) {
                    while (recvfrom(S_socket, rcBuff, PACKET_SIZE, 0, (struct sockaddr *) &addr, &i_addrSize) > 0) {
                        rcIph = (struct ipHeader *) rcBuff;
                        rcIch = (struct icmpHeader *) (rcBuff + sizeof(struct ipHeader));

                        if (rcIch->type == 3) { // I AM CLOSED - thats what he said
                            close_flag = true;
                            i = 3;
                            break;
                        }
                    }
                }
            }
        }

        shutdown(S_socket, SD_RECEIVE);
        closesocket(S_socket);

        // If port is responding with ICMP
        // or something other than UDP, then
        // the port is closed
        if(close_flag || (!close_flag && reply_flag))
            return false;

        return true;
    }

}
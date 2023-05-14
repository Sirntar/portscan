/**
 * IpAddress.h
 * 
 *  Copyright (c) 2023, Tymoteusz Wenerski. All rights reserved.
 * 
 *  Use of this source code is governed by a MIT license
 *  that can be found in the License file.
*/

#ifndef PORTSCAN_IPADDRESS_H
#define PORTSCAN_IPADDRESS_H

#include <cstdint>
#include <string>
#include <sstream>

#ifdef _WIN32
#	include <winsock2.h>
#	include <Ws2tcpip.h>
#else // POSX standard (Linux, BSD, etc.)
#	include <sys/socket.h>
#	include <arpa/inet.h>
#	include <netdb.h>
#	include <unistd.h>
#   include <fcntl.h>
#   include <sys/ioctl.h>
#endif

#define ipv4 uint32_t

namespace scanner::net {

    inline uint32_t bswap32(uint32_t x) {
        uint32_t result;
        
        asm("bswap %0" : "=r" (result) : "0" (x));
        
        return result;
    }

    struct _ipv4Bytes {
        unsigned char b0 = 0;
        unsigned char b1 = 0;
        unsigned char b2 = 0;
        unsigned char b3 = 0;
    };
    typedef struct _ipv4Bytes ipv4Bytes;

    inline bool isBigEndian() {
        union {
            uint32_t i;
            char c[4];
        } test = {0x01020304};

        return test.c[0] == 1;
    }

    union addr_ipv4 {
        explicit addr_ipv4(ipv4 _num) : num(_num) {}
        explicit addr_ipv4(ipv4Bytes _bits) : bits(_bits) {}
        addr_ipv4() = default;

        ipv4Bytes bits{};
        ipv4 num;
    };

    class IpAddress {
        union addr_ipv4 addrIpv4;
    public:
        // constructors
        explicit IpAddress(ipv4 ipAsANumber) : addrIpv4(ipAsANumber) {}
        explicit IpAddress(ipv4Bytes ipAs4Bytes) : addrIpv4(ipAs4Bytes) {}
        explicit IpAddress(const std::string& address);
        explicit IpAddress(const IpAddress* ipAddress);
        IpAddress() = default;

        /**
         * Convert IP addres from string to ipv4
         *
        */
        static ipv4 pton(const std::string& address);
        /**
         * Function is checking if given mask is valid.
         *
         * The algorithm is to check how many changes of value
         * there are in a string of bits in a 32-bit word.
         * One change is allowed, because it means, that the rest of bits
         * should be the same.
         *
         * ex. 00000110 00000000 00000000 00000000 => false, because there are 2 changes
         *     11111111 00000000 00000000 00000000 => true, there is one change
         *     00000000 00000000 00000000 00000000  => false, mask cannot be 0
         *
         */
        static bool is_mask_good(const IpAddress& mask);

        // Getters
        std::string getAsString() const;
        ipv4 getAsNetNumber() const;

        union addr_ipv4 getAsAddr() const { return this->addrIpv4; };

        // Setters
        void setAddr(union addr_ipv4 addr) { this->addrIpv4 = addr; }
        void setAddr(ipv4 num) { this->addrIpv4.num = num; }
        void setAddr(std::string& address) { this->addrIpv4.num = pton(address); }

        // Override
        IpAddress* operator&(const IpAddress& mask) const;
        IpAddress* operator|(const IpAddress& mask) const;
        IpAddress* operator~();
        IpAddress* operator++();
        IpAddress* operator+(const IpAddress& mask);

        bool operator!=(const IpAddress& B) const { return this->addrIpv4.num != B.addrIpv4.num; }
        bool operator==(const IpAddress& B) const { return this->addrIpv4.num == B.addrIpv4.num; }
        bool operator>=(const IpAddress& B) const { return this->addrIpv4.num >= B.addrIpv4.num; }
        bool operator<=(const IpAddress& B) const { return this->addrIpv4.num <= B.addrIpv4.num; }
    };

}

#endif

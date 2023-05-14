/**
 * IpAddress.cc
 * 
 *  Copyright (c) 2023, Tymoteusz Wenerski. All rights reserved.
 * 
 *  Use of this source code is governed by a MIT license
 *  that can be found in the License file.
*/

#include "IpAddress.h"
#include <iostream>

namespace scanner::net {

    int fast_atoi_for_mask(const std::string &str) {
        int val = 0;

        for(char c : str.substr(1, str.size())) // skipping '/
            val = val * 10 + (c++ - '0');

        return val;
    }

    ipv4 get_addr_num_from_mask_short(const std::string &mask){
        ipv4 n_mask = 0b11111111111111111111111111111111;
        int mv = 0;

        mv = 32 - fast_atoi_for_mask(mask);

        if (mv >= 0 && mv < 32) {
            // searching mask is mv bits from n_mask, so we have to shift left
            n_mask <<= mv; 
        } else { // incorrect mask
            return 0;
        }

        if(!isBigEndian()) {
            // Because I've anticipated mask to be in big endian order, 
            // I have to swap bits if architecture is little endian
            n_mask = bswap32(n_mask);
        }
        return n_mask;
    }

    IpAddress::IpAddress(const std::string& address) {
        this->addrIpv4.num = this->pton(address);
    }

    IpAddress::IpAddress(const IpAddress* ipAddress){
        this->addrIpv4 = ipAddress->getAsAddr();
    }

    ipv4 IpAddress::pton(const std::string& address) {
        int res = 0;
        addr_ipv4 addr{};
        std::stringstream err{};

        if(address[0] != '/')
            res = ::inet_pton(AF_INET, address.c_str(), &addr);
        else {
            addr.num = get_addr_num_from_mask_short(address);

            if(addr.num != 0)
                res = 1;
            else
                res = 2;
        }

        if(res == 1)
            return addr.num;
        else if(res == 0) {
            err << "Error: invalid ip! [address: "
                << address
                << "]";
        } else if(res == 2){
            err << "Error: invalid mask! Range is \\1 - \\32. [mask: "
                << address
                << "]";
        } else {
            err << "Error: invalid ip! [address: "
                << address
                << "]"
                << "\n(but... no idea, why...)";
        }
        std::cout << err.str() << "\n";
        return 0; // error
    }

    bool IpAddress::is_mask_good(const IpAddress& mask) {
        ipv4 _mask = mask.getAsNetNumber();
        // only one change is allowed, more changes means
        // that the sequence doesn't have only two substrings
        bool errFlare = false;

        if(_mask == 0)
            return false;

        // the last bit to check
        ipv4 lastMark = _mask & 1;
        for (int i = 0; i < 32; i++) {
            // why not use bitset?
            // without optimization (like -o3 on gcc), 
            // bitset is 11 times slower
            ipv4 current = (_mask >> i) & 1;
            // after shifting, last significant bit will be checked
            if(current != lastMark) {
                if (!errFlare) {
                    errFlare = true;
                    lastMark = current;
                } else { // there were more changes that one
                    return false;
                }
            }
        }
        return true;
    }

    std::string IpAddress::getAsString() const {
        std::stringstream ss{};

        ss  << static_cast<unsigned short>(this->addrIpv4.bits.b0) << '.'
            << static_cast<unsigned short>(this->addrIpv4.bits.b1) << '.'
            << static_cast<unsigned short>(this->addrIpv4.bits.b2) << '.'
            << static_cast<unsigned short>(this->addrIpv4.bits.b3);
        return ss.str();
    }

    ipv4 IpAddress::getAsNetNumber() const {
        if(!isBigEndian())
            return bswap32(this->addrIpv4.num);
        else
            return this->addrIpv4.num;
    }

    IpAddress *IpAddress::operator&(const IpAddress &mask) const {
        auto* ip = new IpAddress();

        ip->setAddr(this->addrIpv4.num & mask.addrIpv4.num);

        return ip;
    }

    IpAddress *IpAddress::operator|(const IpAddress &mask) const {
        auto* ip = new IpAddress();

        ip->setAddr(this->addrIpv4.num | mask.addrIpv4.num);

        return ip;
    }

    IpAddress *IpAddress::operator~() {
        this->setAddr(~this->addrIpv4.num);

        return this;
    }

    IpAddress* IpAddress::operator++() {
        ipv4 val = this->getAsNetNumber();

        if(val < INADDR_BROADCAST)
            val++;
        else
            return nullptr; // not a valid address

        if(!isBigEndian())
            val = bswap32(val);

        this->setAddr(val);

        return this;
    }

    IpAddress *IpAddress::operator+(const IpAddress& mask) {
        auto* ip = new IpAddress();
        ipv4 res = this->getAsNetNumber() + mask.getAsNetNumber();

        if(!isBigEndian())
            res = bswap32(res);

        ip->setAddr(res);

        return ip;
    }
}

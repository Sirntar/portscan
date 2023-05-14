/**
 * SubNet.cc
 * 
 *  Copyright (c) 2023, Tymoteusz Wenerski. All rights reserved.
 * 
 *  Use of this source code is governed by a MIT license
 *  that can be found in the License file.
*/

#include "SubNet.h"

#include <iostream>

namespace scanner::net {

    void SubNet::setSubnetAddress(IpAddress *ip, IpAddress *mask) {
        if(IpAddress::is_mask_good(*mask)) {
            this->id = *ip & *mask;
            this->broadcast = *ip | *(~(*mask));
        } else {
            std::cout << "WARNING: invalid mask!\n";
            this->id = new IpAddress(ip);
        }
    }

    void SubNet::setSubnetAddress(std::string &ip, std::string &mask) {
        auto* _ip = new IpAddress(ip);
        auto* _mask = new IpAddress(mask);

        this->setSubnetAddress(_ip, _mask);

        delete _ip;
        delete _mask;
    }

    SubNet::SubNet(IpAddress *ip, IpAddress *mask) {
        this->setSubnetAddress(ip, mask);
    }

    SubNet::SubNet(std::string &ip, std::string &mask) {
        this->setSubnetAddress(ip, mask);
    }

    SubNet::~SubNet() {
        delete this->id;
        delete this->broadcast;
    }
}
/**
 * SubNet.h
 * 
 *  Copyright (c) 2023, Tymoteusz Wenerski. All rights reserved.
 * 
 *  Use of this source code is governed by a MIT license
 *  that can be found in the License file.
*/

#ifndef PORTSCAN_SUBNET_H
#define PORTSCAN_SUBNET_H

#include "IpAddress.h"

namespace scanner::net {
    class SubNet {
        IpAddress* id = nullptr; // adres sieci
        IpAddress* broadcast = nullptr; // adres rozgłoszeniowy
    public:
        // Constructor
        explicit SubNet(IpAddress* ip, IpAddress* mask);
        explicit SubNet(std::string& ip, std::string& mask);
        SubNet() = default;

        // Destructor
        ~SubNet();

        // Setters
        void setSubnetAddress(IpAddress* ip, IpAddress* mask);
        void setSubnetAddress(std::string& ip, std::string& mask);

        // Getters
        IpAddress getSubnetAddress() { return *id; }
        IpAddress getBroadcastAddress() { return *broadcast; }
    };
}

#endif //PORTSCAN_SUBNET_H

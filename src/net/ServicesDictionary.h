/**
 * ServicesDictionary.h
 * 
 *  Copyright (c) 2023, Tymoteusz Wenerski. All rights reserved.
 * 
 *  Use of this source code is governed by a MIT license
 *  that can be found in the License file.
*/

#ifndef PORTSCAN_SERVICESDICTIONARY_H
#define PORTSCAN_SERVICESDICTIONARY_H

#include <cstdint>
#include <string>
#include <cstdlib>

namespace scanner::net {
    enum CONNECTION_TYPE{TCP, UDP, ALL};

    typedef uint32_t key;

    struct _bsd_leaf{
        key PRIMARY_KEY;
        double priority = 0;

        struct _bsd_leaf* left = nullptr;
        struct _bsd_leaf* right = nullptr;
        struct _bsd_leaf* parent = nullptr;

        std::string tcp_serv = "unknown";
        std::string udp_serv = "unknown";
    };
    typedef struct _bsd_leaf bsd_leaf;

    class ServicesDictionary {
        bsd_leaf* tree = nullptr;
    public:
        ServicesDictionary() { this->loadDatabase("services"); }
        explicit ServicesDictionary(const std::string& filename) { this->loadDatabase(filename.c_str()); }

        ~ServicesDictionary() { this->destroyTree(this->tree); }
    protected:
        void loadDatabase(const std::string& filename);
    public:
        bsd_leaf* getLeaf(key SEARCHED_KEY);
        std::string getService(key PORT, CONNECTION_TYPE protocol);

        void writeTree(const std::string& filename);
    private:
        // dodaj liść
        void insertTree(bsd_leaf* leaf);
        void destroyTree(bsd_leaf* start);
    };
}

#endif //PORTSCAN_SERVICESDICTIONARY_H

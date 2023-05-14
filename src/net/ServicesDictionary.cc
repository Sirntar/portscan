/**
 * ServicesDictionary.cc
 * 
 *  Copyright (c) 2023, Tymoteusz Wenerski. All rights reserved.
 * 
 *  Use of this source code is governed by a MIT license
 *  that can be found in the License file.
*/

#include "ServicesDictionary.h"

#include <iostream>
#include <fstream>

namespace scanner::net {

    void ServicesDictionary::loadDatabase(const std::string& filename) {
        std::ifstream f(filename, std::ios::in);
        bsd_leaf* leaf = nullptr;

        int counter = 0;
        key port_key = 0;
        std::string tcp = "", udp = "";
        double priority = 0.0;

        if(!f.is_open()){
            std::cerr << "ERROR: Cannot open file with services names...\n";
            return;
        }

        while(f >> port_key >> tcp >> udp >> priority){
            leaf = new bsd_leaf();

            leaf->PRIMARY_KEY = port_key;
            leaf->priority = priority;

            this->insertTree(leaf);

            leaf->tcp_serv = tcp;
            leaf->udp_serv = udp;
            counter++;
        }

        std::cout << "Loaded " << counter << " known ports.." << std::endl;

        f.close();
    }

    bsd_leaf *ServicesDictionary::getLeaf(key k) {
        bsd_leaf *current = this->tree;
        /*
         * W "Biblii" (Wprowadzenie do Algorytmów) jest napisane,
         * że na większości komputerów nierekurencyjna implementacja będzie szybsza,
         * więc ta dam:
         */
        while(current != nullptr && current->PRIMARY_KEY != k) {
            if(k < current->PRIMARY_KEY)
                current = current->left;
            else
                current = current->right;
        }
        return current;
    }

    void ServicesDictionary::insertTree(bsd_leaf *leaf) {
        bsd_leaf* parent = this->tree;

        if(leaf == nullptr)
            return; // pusty liść - nic nie dodam

        leaf->parent = nullptr;

        // poszukuję rodzica dla liścia
        while(parent != nullptr) {
            leaf->parent = parent; // ustalam ojca

            if(leaf->PRIMARY_KEY < parent->PRIMARY_KEY) // jeśli mniejszy od ojca klucz
                parent = parent->left; // to ojciec dla liścia będzie na lewo
            else
                parent = parent->right; // w przeciwnym wypadku - znajdę go na prawo
        }

        parent = leaf->parent; // zwracam prawidłowe ojcostwo

        if(parent == nullptr)
            this->tree = leaf; // drzewo nie ma korzenia, więc mu go stworzę
        else if(leaf->PRIMARY_KEY < parent->PRIMARY_KEY)
            parent->left = leaf; // większe bądź równe liście będą na prawo
        else
            parent->right = leaf; // mniejsze liście będą zawsze na lewo
    }

    /**
     * Usuń drzewo od konkretnego liścia
     *
     * @param start
     */
    void ServicesDictionary::destroyTree(bsd_leaf* start) {
        if(start == nullptr)
            return;

        if(start->left != nullptr)
            this->destroyTree(start->left);
        if(start->right != nullptr)
            this->destroyTree(start->right);

        if(start->parent != nullptr) {
            if(start->parent->left == start)
                start->parent->left = nullptr;
            else
                start->parent->right = nullptr;
        }
        delete start;
    }

    std::string ServicesDictionary::getService(key PORT, CONNECTION_TYPE protocol) {
        bsd_leaf* searched = this->getLeaf(PORT);

        if(searched == nullptr)
            return "unknown";
        return protocol == TCP ? searched->tcp_serv : searched->udp_serv;
    }

    void treeWalker(bsd_leaf* leaf, std::fstream& f) {
        if(leaf != nullptr) {
            f << leaf->PRIMARY_KEY << " " << leaf->tcp_serv << " " << leaf->udp_serv << " " << std::fixed << leaf->priority << std::endl;
            treeWalker(leaf->left, f);
            treeWalker(leaf->right, f);
        }
    }

    void ServicesDictionary::writeTree(const std::string &filename) {
        std::fstream f(filename, std::ios::out);

        if(!f.good()){
            std::cerr << "ERROR: Cannot create file\n";
            return;
        }

        treeWalker(this->tree, f);

        f.close();
    }
}
/**
 * ThreadPool.h
 * 
 *  Copyright (c) 2023, Tymoteusz Wenerski. All rights reserved.
 * 
 *  Use of this source code is governed by a MIT license
 *  that can be found in the License file.
 * 
 * This class is one of the possible implementations.
 * In this project I didn't need advanced functionality,
 * so I've decided to write my own implementation.
*/

#ifndef THREAD_POOL_H
#define THREAD_POOL_H

#include <queue>
#include <vector>
#include <functional>

#include <thread>
#include <mutex>
#include <condition_variable>

#include <iostream>

namespace scanner::async {
    class ThreadPool {
    private:
        std::queue<std::function<void()>> tasks;
        std::vector<std::thread> threads;

        std::mutex tasks_mutex;
        std::condition_variable task_available;
        std::condition_variable task_done;
        bool is_running = false;
        bool is_waiting = false;

        void threadLoop() {
            while(is_running) {
                std::function<void()> task;
                {
                    std::unique_lock<std::mutex> lock(tasks_mutex);

                    task_available.wait(lock, [this]() {
                        return !is_running || !tasks.empty();
                    });

                    task = tasks.front();
                    tasks.pop();
                }

                if (is_running) {
                    task();

                    if (is_waiting) {
                        task_done.notify_one();
                    }
                }
            }
        }

    public:
        ThreadPool() {
            createThreads(std::thread::hardware_concurrency());
        }

        ThreadPool(int how_many_threads) {
            createThreads(how_many_threads);
        }

        ~ThreadPool() {
            waitForThreads();
            destroyThreads();
        }

        void createThreads(int how_many) {
            is_running = true;

            for (int i = 0; i < how_many; i++) {
                threads.emplace_back(&ThreadPool::threadLoop, this);
            }
        }

        void destroyThreads() {
            is_running = false;
            task_available.notify_all();
            
            for (int i = 0; i < threads.size(); i++) {
                threads[i].join();
            }
        }

        void waitForThreads() {
            is_waiting = true;
            std::unique_lock<std::mutex> lock(tasks_mutex);

            task_done.wait(lock, [this] {
                return tasks.size() == 0;
            });

            is_waiting = false;
        }

        void push(const std::function<void()>& func) {
            std::lock_guard<std::mutex> lock(tasks_mutex);
            tasks.push(func);
        }
    };
}

#endif
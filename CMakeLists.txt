cmake_minimum_required(VERSION 3.22)
project(portscan)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static")

set(PORTSCAN_HEADERS
    src/async/AsyncCout.h
    src/async/ThreadPool.h
    src/net/IpAddress.h
    src/net/SubNet.h
    src/net/ServicesDictionary.h
    src/scanner/PortScanner.h
)

set(PORTSCAN_SOURCES
    src/main.cc
    src/net/IpAddress.cc
    src/net/SubNet.cc
    src/net/ServicesDictionary.cc
    src/scanner/TCP.cc
    src/scanner/UDP.cc
    src/scanner/Print.cc
    src/scanner/PortScanner.cc
    src/main.cc
)

add_executable(portscan)
target_sources(portscan PRIVATE ${PORTSCAN_HEADERS} ${PORTSCAN_SOURCES})

find_package(Threads REQUIRED)

if(WIN32)
    target_link_libraries(portscan Threads::Threads ws2_32)
else()
    target_link_libraries(portscan Threads::Threads)
endif(WIN32)

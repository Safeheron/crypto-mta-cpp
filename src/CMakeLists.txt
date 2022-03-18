cmake_minimum_required(VERSION 3.10)
project(CryptoMTA)

set(CMAKE_CXX_STANDARD 11)
SET(CMAKE_BUILD_TYPE "Release")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -Wall -Wextra -Wno-unused-parameter -Wno-unused-variable")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2 -Wall -Wextra -Wno-unused-parameter -Wno-unused-variable")

find_package(PkgConfig REQUIRED)
pkg_search_module(PROTOBUF REQUIRED protobuf)  # depend on pkg-config, this looks for opencv.pc file

#set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)
find_package(CryptoBN REQUIRED)
find_package(CryptoEncode REQUIRED)
find_package(CryptoCurve REQUIRED)
find_package(CryptoPaillier REQUIRED)
find_package(CryptoZKP REQUIRED)

add_library(${PROJECT_NAME} SHARED
        crypto-mta/mta.cpp
        crypto-mta/mta.pb.cc
        )

target_include_directories(${PROJECT_NAME} PUBLIC
        ${CryptoBN_INCLUDE_DIRS}
        ${CryptoEncode_INCLUDE_DIRS}
        ${CryptoCurve_INCLUDE_DIRS}
        ${CryptoPaillier_INCLUDE_DIRS}
        ${CryptoZKP_INCLUDE_DIRS}
        ${PROTOBUF_INCLUDE_DIRS}
        ${OPENSSL_INCLUDE_DIR}
        )

TARGET_LINK_LIBRARIES(${PROJECT_NAME} ${PROTOBUF_LIBRARIES}
        CryptoBN
        CryptoEncode
        CryptoCurve
        CryptoPaillier
        CryptoZKP
        OpenSSL::Crypto
        -ldl
        )
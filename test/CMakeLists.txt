find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})

find_package(PkgConfig REQUIRED)
pkg_search_module(PROTOBUF REQUIRED protobuf)  # this looks for opencv.pc file

include_directories(
        "../src"
        ${PROTOBUF_INCLUDE_DIRS})

add_executable(mta-test mta-test.cpp)
target_link_libraries(mta-test
        CryptoMTA
        ${GTEST_BOTH_LIBRARIES}
        pthread )
add_test(NAME mta-test COMMAND mta-test)



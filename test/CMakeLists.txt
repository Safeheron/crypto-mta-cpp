find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})

find_package(PkgConfig REQUIRED)
pkg_search_module(PROTOBUF REQUIRED protobuf)  # this looks for opencv.pc file

include_directories(
        "../src"
        ${PROTOBUF_INCLUDE_DIRS})

option(ENABLE_ASSEMBLE "Enable assemble" OFF)
if (NOT ${ENABLE_ASSEMBLE})
    link_libraries(CryptoMTA
            ${GTEST_BOTH_LIBRARIES}
            pthread )
else()
    link_libraries(${CMAKE_PROJECT_NAME}
            ${GTEST_BOTH_LIBRARIES}
            pthread )
endif()

add_executable(mta-test mta-test.cpp)
add_test(NAME mta-test COMMAND mta-test)



cmake_minimum_required(VERSION 3.4.1)

# configure import libs
set(distribution_DIR ${CMAKE_SOURCE_DIR}/../../../../distribution)

add_library(lib_gmath STATIC IMPORTED)
set_target_properties(lib_gmath PROPERTIES IMPORTED_LOCATION
    ${distribution_DIR}/gmath/lib/${ANDROID_ABI}/libgmath.a)

# gperf
add_library(lib_gperf SHARED IMPORTED)
set_target_properties(lib_gperf PROPERTIES IMPORTED_LOCATION
    ${distribution_DIR}/gperf/lib/${ANDROID_ABI}/libgperf.so)

# openssl
add_library(lib_crypto SHARED IMPORTED)
set_target_properties(lib_crypto PROPERTIES IMPORTED_LOCATION
    ${distribution_DIR}/openssl/lib/${ANDROID_ABI}/libcrypto_1_0_0.so)

add_library(lib_ssl STATIC IMPORTED)
set_target_properties(lib_ssl PROPERTIES IMPORTED_LOCATION
    ${distribution_DIR}/openssl/lib/${ANDROID_ABI}/libssl.a)

# build application's shared lib
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu++11")

add_library(hello-libs SHARED
            hello-libs.cpp)

target_include_directories(hello-libs PRIVATE
                           ${distribution_DIR}/gmath/include
                           ${distribution_DIR}/gperf/include
                           ${distribution_DIR}/openssl/include)

target_link_libraries(hello-libs

                        lib_crypto
                        lib_ssl
                        android
                        lib_gmath
                        lib_gperf
                        log)

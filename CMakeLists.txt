cmake_minimum_required(VERSION 3.0)
project(chacha20_poly1305 C)

set(CMAKE_C_STANDARD 11)
SET(CMAKE_C_FLAGS "-Wall -Wextra")
SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS} -g3 -rdynamic -export-dynamic -O0")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS} -O3 -march=native")

add_library(chacha20_poly1305 chacha20_poly1305.c)
target_include_directories(${PROJECT_NAME} PUBLIC ${PROJECT_SOURCE_DIR})

add_executable(rfc_tests
        rfc_tests/tests.c
        rfc_tests/poly1305_test.c
        rfc_tests/chacha20_test.c
        rfc_tests/aead_test.c)

target_link_libraries(rfc_tests chacha20_poly1305)

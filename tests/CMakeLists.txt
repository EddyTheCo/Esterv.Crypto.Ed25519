cmake_minimum_required(VERSION 3.11 FATAL_ERROR)

project(testing VERSION 0.1 DESCRIPTION "diferent tests for the library" LANGUAGES CXX)

add_executable(rfc8032 rfc8032.cpp)
target_link_libraries(rfc8032 PRIVATE  qed25519)
add_test(NAME rfc8032 COMMAND rfc8032)

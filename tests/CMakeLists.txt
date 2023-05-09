cmake_minimum_required(VERSION 3.11 FATAL_ERROR)

project(testing VERSION 0.1 DESCRIPTION "diferent tests for the library" LANGUAGES CXX)


add_executable(rfc8032 rfc8032.cpp)
target_link_libraries(rfc8032 PRIVATE qed25519)
add_test(NAME rfc8032 COMMAND rfc8032)

if (WIN32 AND BUILD_SHARED_LIBS)
    add_custom_command(
        TARGET  POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_RUNTIME_DLLS:rfc8032> $<TARGET_FILE_DIR:rfc8032>
        COMMAND_EXPAND_LISTS
    )
endif ()

add_executable(tip14 tip14.cpp)
target_link_libraries(tip14 PRIVATE qed25519)
add_test(NAME tip14 COMMAND tip14)

if (WIN32 AND BUILD_SHARED_LIBS)
    add_custom_command(
        TARGET  POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_RUNTIME_DLLS:tip14> $<TARGET_FILE_DIR:tip14>
        COMMAND_EXPAND_LISTS
    )
endif ()


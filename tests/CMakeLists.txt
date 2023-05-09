cmake_minimum_required(VERSION 3.11 FATAL_ERROR)

project(testing VERSION 0.1 DESCRIPTION "diferent tests for the library" LANGUAGES CXX)

message(STATUS "Setting tests")

foreach(app rfc8032 tip14)
message(STATUS "Setting Test ${app}")
add_executable(${app} ${app}.cpp)
target_link_libraries(${app} PRIVATE qed25519)
add_test(NAME ${app} COMMAND ${app})

if (WIN32 AND BUILD_SHARED_LIBS)
    add_custom_command(
        TARGET  POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_RUNTIME_DLLS:${app}> $<TARGET_FILE_DIR:${app}>
        COMMAND_EXPAND_LISTS
    )
endif ()
endforeach()


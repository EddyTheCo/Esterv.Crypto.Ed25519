cmake_minimum_required(VERSION 3.11 FATAL_ERROR)
include(local_conf.cmake OPTIONAL)
project(Qted25519 VERSION 0.1 DESCRIPTION "qt interface for ed25519 " LANGUAGES C CXX)


set(default_build_type "Release")
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
	message(STATUS "Setting build type to '${default_build_type}' as none was specified.")
	set(CMAKE_BUILD_TYPE "${default_build_type}" CACHE
		STRING "Choose the type of build." FORCE)
	# Set the possible values of build type for cmake-gui
	set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
		"Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

set_property(GLOBAL PROPERTY USE_FOLDERS ON)
set(CMAKE_CXX_EXTENSIONS OFF)
option(USE_INTERNAL "On or off" OFF)
include(CMakeDependentOption)
cmake_dependent_option(USE_SODIUM "Use Sodium" ON "NOT USE_INTERNAL" OFF)
if(EMSCRIPTEN)
	option(sodium_USE_STATIC_LIBS "On or off" ON)
endif()
if(USE_INTERNAL)
	file(GLOB SRC_FILES src/*.c src/*.h)
	add_library(qed25519  qed25519.cpp include/crypto/qed25519.hpp ${SRC_FILES})
	target_compile_definitions(qed25519 PRIVATE USE_INTERNAL)
endif(USE_INTERNAL)

if(USE_SODIUM)
	include(CMake/FindSodium.cmake)
	add_library(qed25519  qed25519.cpp include/crypto/qed25519.hpp )
	target_link_libraries(qed25519 PRIVATE sodium )
	target_compile_definitions(qed25519 PRIVATE USE_SODIUM)
endif(USE_SODIUM)

find_package(Qt6 REQUIRED COMPONENTS Core)
target_link_libraries(qed25519 PUBLIC  Qt6::Core)


target_include_directories(qed25519 PUBLIC  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
	"$<INSTALL_INTERFACE:include>")
target_include_directories(qed25519 PRIVATE  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
	"$<INSTALL_INTERFACE:src>")

install(TARGETS qed25519 EXPORT qed25519Targets DESTINATION lib)
install(DIRECTORY include/ DESTINATION include/)

install(EXPORT qed25519Targets
	FILE qed25519Targets.cmake
	DESTINATION lib/cmake/qed25519
	)
include(CMakePackageConfigHelpers)
# generate the config file that is includes the exports
configure_package_config_file(${CMAKE_CURRENT_SOURCE_DIR}/Config.cmake.in
	"${CMAKE_CURRENT_BINARY_DIR}/qed25519Config.cmake"
	INSTALL_DESTINATION "lib/cmake/qed25519"
	NO_SET_AND_CHECK_MACRO
	NO_CHECK_REQUIRED_COMPONENTS_MACRO
	)
write_basic_package_version_file(
	"${CMAKE_CURRENT_BINARY_DIR}/qed25519ConfigVersion.cmake"
	VERSION "0.1.1.0"
	COMPATIBILITY AnyNewerVersion
	)
install(FILES
	${CMAKE_CURRENT_BINARY_DIR}/qed25519Config.cmake
	${CMAKE_CURRENT_BINARY_DIR}/qed25519ConfigVersion.cmake
	DESTINATION lib/cmake/qed25519
	)
export(EXPORT qed25519Targets
	FILE "${CMAKE_CURRENT_BINARY_DIR}/qed25519Targets.cmake"
	)
if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
	include(CTest)
endif()
if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME AND BUILD_TESTING)
	add_subdirectory(tests)
endif()

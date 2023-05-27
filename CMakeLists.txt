cmake_minimum_required(VERSION 3.11 FATAL_ERROR)
include(local_conf.cmake OPTIONAL)

include(FetchContent)
FetchContent_Declare(
	ccommon
	GIT_REPOSITORY https://github.com/EddyTheCo/Common.git
	GIT_TAG main
	)
FetchContent_MakeAvailable(ccommon)
version_from_git(
	LOG       OFF
  TIMESTAMP "%Y%m%d%H%M%S"
)
project(Qted25519 VERSION ${VERSION} DESCRIPTION "Qt interface for ed25519 " LANGUAGES  CXX C)


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
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)

find_package(Qt6 COMPONENTS Core)

if (Qt6_FOUND)
qt_standard_project_setup()
endif(Qt6_FOUND)

file(GLOB SRC_FILES src/*.c src/*.cpp src/*.h)
add_library(qed25519  include/crypto/qed25519.hpp ${SRC_FILES})

if (Qt6_FOUND)
target_link_libraries(qed25519 PUBLIC  Qt6::Core)
endif(Qt6_FOUND)

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
	VERSION ${VERSION}
	COMPATIBILITY SameMajorVersion
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
    set(CPACK_PACKAGE_FILE_NAME "${PROJECT_NAME}-v${SEMVER}-${CMAKE_SYSTEM_NAME}_${CMAKE_SYSTEM_VERSION}-${CMAKE_SYSTEM_PROCESSOR}-${CMAKE_CXX_COMPILER_ID}")
    if(NOT BUILD_SHARED_LIBS)	    
    set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_FILE_NAME}-static")
    endif(NOT BUILD_SHARED_LIBS)		    
    include(CPack)
endif()
if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME AND BUILD_TESTING)
    add_subdirectory(tests)
endif()
if(BUILD_DOCS)
	get_target_property(build_docs cmake_build_docs SOURCES)
	include(${build_docs})
endif()

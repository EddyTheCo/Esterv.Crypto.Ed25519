cmake_minimum_required(VERSION 3.11 )

include(${CMAKE_CURRENT_BINARY_DIR}/local_conf.cmake OPTIONAL)

include(FetchContent)
FetchContent_Declare(
	ccommon
	GIT_REPOSITORY https://github.com/EddyTheCo/Common.git
	GIT_TAG v0.3.1
	)
FetchContent_MakeAvailable(ccommon)
version_from_git(
	LOG       OFF
	TIMESTAMP "%Y%m%d%H%M%S"
	)

project(Qted25519 VERSION ${VERSION} DESCRIPTION "Interface for ed25519 " LANGUAGES  CXX C)



set_property(GLOBAL PROPERTY USE_FOLDERS ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
include(GNUInstallDirs)

find_package(Qt6 COMPONENTS Core)

if (Qt6_FOUND)
	qt_standard_project_setup()

	file(GLOB SRC_FILES src/*.c src/*.cpp src/*.h)
	add_library(qed25519  ${SRC_FILES})
	add_library(${PROJECT_NAME}::qed25519 ALIAS qed25519)
	set_target_properties(qed25519 PROPERTIES VERSION ${VERSION} SOVERSION ${VERSION_MAJOR})

	target_link_libraries(qed25519 PUBLIC  Qt6::Core)

	target_include_directories(qed25519 PUBLIC  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
		"$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/Esterv/>")

	install(TARGETS qed25519
		EXPORT ${PROJECT_NAME}-config
		DESTINATION ${CMAKE_INSTALL_LIBDIR}
		COMPONENT ed25519
		RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}" COMPONENT ed25519
		)
	install(DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/include/
		DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/Esterv
		COMPONENT ${PROJECT_NAME}
		)

	build_exports()
	if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
		build_cpack()
		if(BUILD_TESTING)
			include(CTest)
			add_subdirectory(tests)
		endif(BUILD_TESTING)
	endif(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
endif(Qt6_FOUND)
if(BUILD_DOCS)
	build_docs()
endif(BUILD_DOCS)

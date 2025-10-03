cmake_minimum_required(VERSION 3.14...4.0)

if (CMAKE_VERSION VERSION_GREATER_EQUAL "3.24.0")
    cmake_policy(SET CMP0135 NEW)
endif()

project(asio
    VERSION 1.0.0
    DESCRIPTION "A memory safe focus `C framework`, combining RAII, libuv, coroutine, and other concurrency primitives."
    HOMEPAGE_URL "https://zelang-dev.github.io/c-asio/"
	LANGUAGES C
)

set(CMAKE_C_STANDARD 90)

include(CMakeDependentOption)
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
include(FetchContent)
include(CTest)

message("Generated with config types: ${CMAKE_CONFIGURATION_TYPES}")

set(CMAKE_CONFIGURATION_TYPES=Debug;Release)
set(BUILD_DIR ${CMAKE_CURRENT_SOURCE_DIR}/build)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${BUILD_DIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/built")
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

find_package(raii QUIET)
if(NOT raii_FOUND)
    FetchContent_Declare(raii
        URL https://github.com/zelang-dev/c-raii/archive/refs/tags/2.2.3.zip
        URL_MD5 f1cc164554b8c3e64c709cb4e192878a
    )
    FetchContent_MakeAvailable(raii)
endif()

find_package(libuv QUIET)
if(NOT libuv_FOUND)
    FetchContent_Declare(libuv
        URL https://github.com/libuv/libuv/archive/refs/tags/v1.51.0.zip
        URL_MD5 89997b2ecd52664fa117ffc82560f5eb
    )
    add_definitions("/wd4701 /wd4245 /wd4244 /wd4244 /wd4267")
    FetchContent_MakeAvailable(libuv)
endif()

find_package(opentls QUIET)
if(NOT opentls_FOUND)
    FetchContent_Declare(opentls
        URL https://github.com/zelang-dev/openTLS/archive/refs/tags/4.1.9.zip
        URL_MD5 bceb14cc4b24aa16b3da3805a26bc2fe
    )
    if(WIN32)
        add_definitions(-DOPENSSL_MSVC_STATIC_RT=TRUE)
        add_definitions(-DNO_GETTIMEOFDAY)
        include_directories(${OPENSSL_INCLUDE_DIR})
    endif()
    FetchContent_MakeAvailable(opentls)
endif()

set(lib_files
    ${CMAKE_CURRENT_SOURCE_DIR}/src/asio.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ssl.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/uv_http.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/uv_tls.c
)

add_library(${PROJECT_NAME} STATIC ${lib_files})
add_library(ASIO::ASYNC ALIAS ${PROJECT_NAME})
target_include_directories(${PROJECT_NAME} PRIVATE $<BUILD_INTERFACE:${RAII_INCLUDE_DIR}
	$<INSTALL_INTERFACE:${RAII_INCLUDE_DIR})
target_include_directories(${PROJECT_NAME}	PRIVATE $<BUILD_INTERFACE:${OPENTLS_INCLUDE_DIR}
	$<INSTALL_INTERFACE:${OPENTLS_INCLUDE_DIR})
target_include_directories(${PROJECT_NAME}	PRIVATE $<BUILD_INTERFACE:${OPENSSL_INCLUDE_DIR}
	$<INSTALL_INTERFACE:${OPENSSL_INCLUDE_DIR})
target_include_directories(${PROJECT_NAME} PUBLIC
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
	$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

target_link_libraries(${PROJECT_NAME} PUBLIC ${OPENSSL_SSL_LIBRARY})
target_link_libraries(${PROJECT_NAME} PUBLIC ${OPENSSL_CRYPTO_LIBRARY})
target_link_libraries(${PROJECT_NAME} PUBLIC opentls)
target_link_libraries(${PROJECT_NAME} PUBLIC uv_a)
target_link_libraries(${PROJECT_NAME} PUBLIC raii)

set_property(TARGET ${PROJECT_NAME} PROPERTY POSITION_INDEPENDENT_CODE True)

if(UNIX)
    if(APPLE)
        set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wno-format -D USE_DEBUG ")
    else()
        set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -rdynamic -Wno-format -D USE_DEBUG -D USE_VALGRIND")
    endif()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -fomit-frame-pointer -Wno-return-type")
else()
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} /D USE_DEBUG ")
    add_definitions(-D_CRT_SECURE_NO_DEPRECATE)
    add_definitions("/wd4244 /wd4267 /wd4033 /wd4715 /wd4996")
endif()

find_package(ZLIB CONFIG)
if(ZLIB_FOUND)
    target_include_directories(${PROJECT_NAME} PRIVATE $<BUILD_INTERFACE:${ZLIB_INCLUDE_DIR} $<INSTALL_INTERFACE:${INSTALL_INC_DIR})
    message(STATUS "Cmake FindZLIB: using ZLIB includes at: ${ZLIB_INCLUDE_DIR}")
    message(STATUS "Cmake FindZLIB: using ZLIB libraries: ${ZLIB_LIBRARIES}")
else()
    FetchContent_Declare(ZLIB
        URL https://github.com/madler/zlib/releases/download/v1.3.1/zlib-1.3.1.tar.gz
        URL_MD5 9855b6d802d7fe5b7bd5b196a2271655
    )
    FetchContent_MakeAvailable(ZLIB)
    option(ZLIB_BUILD_MINIZIP "Enable building libminizip contrib" OFF)
    option(ZLIB_BUILD_EXAMPLES "Enable Zlib Examples as tests" OFF)
    option(ZLIB_INSTALL "Enable installation of zlib" ON)
    set(ZLIB_BUILD_EXAMPLES OFF CACHE BOOL "Build tests" FORCE)
    set(ZLIB_BUILD_MINIZIP OFF CACHE BOOL "Build libminizip" FORCE)
    set(ZLIB_INSTALL ON CACHE BOOL "Install zlib" FORCE)
    target_include_directories(${PROJECT_NAME} PRIVATE $<BUILD_INTERFACE:${INSTALL_INC_DIR} $<INSTALL_INTERFACE:${INSTALL_INC_DIR})
endif()
target_link_libraries(${PROJECT_NAME} PUBLIC ${ZLIB_LIBRARIES})

# enable the address sanitizer to catch bugs
option(ENABLE_ASAN "Enable AddressSanitizer for Debug builds" OFF)

# Only add sanitizer flags in Debug builds
if(ENABLE_ASAN AND CMAKE_BUILD_TYPE MATCHES Debug)
    if(MSVC)
        # MSVC supports address sanitizer with /fsanitize=address.
        set(ASAN_COMPILE_FLAG "/fsanitize=address")
        set(ASAN_LINK_FLAG "/fsanitize=address")
    else()
        # GCC/Clang
        set(ASAN_COMPILE_FLAG "-fsanitize=address")
        set(ASAN_LINK_FLAG "-fsanitize=address")
    endif()
    target_compile_options(${PROJECT_NAME} PUBLIC ${ASAN_COMPILE_FLAG})
    target_link_options(${PROJECT_NAME} PUBLIC ${ASAN_LINK_FLAG})
endif()

if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    option(BUILD_EXAMPLES "whether or not examples should be built" ON)
    option(BUILD_TESTS "whether or not tests should be built" ON)

    if(BUILD_EXAMPLES)
        add_subdirectory(examples)
    endif()
    if(BUILD_TESTS)
        enable_testing()
        add_subdirectory(tests)
    endif()
endif()

set_target_properties(${PROJECT_NAME} PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(${PROJECT_NAME} PROPERTIES SOVERSION ${PROJECT_VERSION_MAJOR})

set(_fmt TGZ)
if(WIN32)
  set(_fmt ZIP)
endif()

set(CPACK_GENERATOR ${_fmt})
set(CPACK_ARCHIVE_COMPONENT_INSTALL ON)
set(CPACK_DEB_COMPONENT_INSTALL ON)
set(CPACK_RPM_COMPONENT_INSTALL ON)
set(CPACK_NUGET_COMPONENT_INSTALL ON)
set(CPACK_WIX_COMPONENT_INSTALL ON)
set(CPACK_NSIS_MODIFY_PATH ON)
set(CPACK_COMPONENTS_ALL_IN_ONE_PACKAGE 1)
set(CPACK_VERBATIM_VARIABLES YES)

set(CPACK_SOURCE_IGNORE_FILES
	"~$"
	"\\\\.svn/"
	"/CMakeFiles/"
	"/CMakeCache*"
	"/cmake_install\\\\.cmake$"
	"/cmake_uninstall\\\\.cmake$"
	"^_CPack_.*/"
	"/CPack*"
	"\\\\.o$"
	"/m4/"
	"/build/"
	"/built/"
)

set(INCLUDE_INSTALL_DIR ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME}
    CACHE PATH "Location of header files" )

set(SYSCONFIG_INSTALL_DIR ${CMAKE_INSTALL_SYSCONFDIR}/${PROJECT_NAME}
    CACHE PATH "Location of configuration files" )

configure_package_config_file(asioConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/asioConfig.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
  PATH_VARS INCLUDE_INSTALL_DIR SYSCONFIG_INSTALL_DIR)

write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/asioConfigVersion.cmake
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion )

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/asioConfig.cmake
              ${CMAKE_CURRENT_BINARY_DIR}/asioConfigVersion.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME} )

set(CMAKE_INSTALL_CONFIG_NAME ${CMAKE_BUILD_TYPE})

set(CPACK_PACKAGE_DIRECTORY "${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}/Package")
set(CPACK_PACKAGE_FILE_NAME ${CPACK_PACKAGE_NAME})
set(CPACK_PACKAGE_INSTALL_DIRECTORY ${PROJECT_NAME})

set(CPACK_PACKAGE_CONTACT "lstubbs@zelang.dev")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Lawrence Stubbs <${CPACK_PACKAGE_CONTACT}>")
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
set(CPACK_COMPONENTS_GROUPING ALL_COMPONENTS_IN_ONE)
SET(CPACK_COMPONENT_LIBRARIES_DISPLAY_NAME "C framework library")
SET(CPACK_COMPONENT_LIBRARIES_DESCRIPTION "A memory safe focus `C framework`, combining RAII, libuv, coroutine, and other concurrency primitives.")

set(CPACK_RESOURCE_FILE_LICENSE ${CMAKE_CURRENT_SOURCE_DIR}/LICENSE.md)
set(CPACK_RESOURCE_FILE_README ${CMAKE_CURRENT_SOURCE_DIR}/README.md)

set(CPACK_PACKAGE_VENDOR "https://github.com/zelang-dev")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION ${PROJECT_DESCRIPTION})

set(CPACK_RPM_PACKAGE_LICENSE "MIT")
set(CPACK_RPM_PACKAGE_URL "https://zelang-dev.github.io/c-asio/")
set(CPACK_RPM_PACKAGE_ARCHITECTURE "noarch")

set(CMAKE_INSTALL_CONFIG_NAME ${CMAKE_BUILD_TYPE})
install(
    TARGETS ${PROJECT_NAME} raii uv opentls
    EXPORT "${PROJECT_NAME}Targets"
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(
    EXPORT "${PROJECT_NAME}Targets"
    FILE "${PROJECT_NAME}Targets.cmake"
    NAMESPACE ASIO::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
)

install(TARGETS ${PROJECT_NAME} DESTINATION lib)
file(GLOB HEADER_LIST "include/*.h")
install(FILES ${HEADER_LIST} DESTINATION include)

set(CPACK_INSTALL_CMAKE_CONFIGURATIONS Release)
include(CPack)

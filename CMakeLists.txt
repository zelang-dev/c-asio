cmake_minimum_required(VERSION 3.11...3.14)

if (CMAKE_VERSION VERSION_GREATER_EQUAL "3.24.0")
    cmake_policy(SET CMP0135 NEW)
endif()

project(uv_coroutine LANGUAGES C)

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
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake;${CMAKE_MODULE_PATH}")

find_package(raii QUIET)
if(NOT raii_FOUND)
    FetchContent_Declare(raii
        URL https://github.com/zelang-dev/c-raii/archive/refs/heads/main.zip
        URL_MD5 a563dba478aea631baf8167750bc943d
    )
    FetchContent_MakeAvailable(raii)
endif()

find_package(libuv QUIET)
if(NOT libuv_FOUND)
    FetchContent_Declare(libuv
        URL https://github.com/libuv/libuv/archive/refs/tags/v1.51.0.zip
        URL_MD5 89997b2ecd52664fa117ffc82560f5eb
    )
    FetchContent_MakeAvailable(libuv)
endif()

file(GLOB lib_files
    ${CMAKE_CURRENT_SOURCE_DIR}/src/*.c
)

add_library(uv_coro STATIC ${lib_files})
set_property(TARGET uv_coro PROPERTY POSITION_INDEPENDENT_CODE True)
target_link_libraries(uv_coro PUBLIC uv_a)
target_include_directories(uv_coro AFTER PUBLIC $<BUILD_INTERFACE:${RAII_INCLUDE_DIR} $<INSTALL_INTERFACE:${RAII_INCLUDE_DIR})
target_link_libraries(uv_coro PUBLIC raii)

if(UNIX)
    find_package(OpenSSL 0.9.8...<2.0.0)
else()
    find_package(OpenSSL 0.9.8...<1.1.0)
endif()

if(OPENSSL_FOUND)
    target_include_directories(uv_coro PUBLIC $<BUILD_INTERFACE:${OPENSSL_INCLUDE_DIR} $<INSTALL_INTERFACE:${OPENSSL_INCLUDE_DIR})
    if(WIN32)
        add_definitions(-DOPENSSL_USE_STATIC_LIBS=TRUE)
        add_definitions(-DOPENSSL_MSVC_STATIC_RT=TRUE)
        add_definitions(-DNO_GETTIMEOFDAY)
    endif()
    target_link_libraries(uv_coro PUBLIC ${OPENSSL_CRYPTO_LIBRARY})
    target_link_libraries(uv_coro PUBLIC ${OPENSSL_SSL_LIBRARY})
else()
    find_package(LibreSSL QUIET)
    if(NOT LibreSSL_FOUND)
        FetchContent_Declare(libressl
            URL https://github.com/libressl/portable/releases/download/v4.1.0/libressl-4.1.0.tar.gz
            URL_MD5 18079dcf72a398d8c188e67e30c1dc13
        )
        option(LIBRESSL_APPS "Build apps" OFF)
        option(LIBRESSL_TESTS "Build tests" OFF)
        FetchContent_MakeAvailable(libressl)
    endif()
    set(LIBRESSL_APPS OFF CACHE BOOL "Build apps" FORCE)
    set(LIBRESSL_TESTS OFF CACHE BOOL "Build tests" FORCE)
    target_include_directories(uv_coro PUBLIC $<BUILD_INTERFACE:${LibreSSL_INCLUDE_DIR} $<INSTALL_INTERFACE:${LibreSSL_INCLUDE_DIR})
    target_link_libraries(uv_coro PUBLIC crypto)
    target_link_libraries(uv_coro PUBLIC ssl)
endif()

target_include_directories(uv_coro
    PUBLIC $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

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

# enable the address sanitizer to catch bugs
option(ENABLE_ASAN "Enable AddressSanitizer for Debug builds" ON)

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
    target_compile_options(uv_coro PUBLIC ${ASAN_COMPILE_FLAG})
    target_link_options(uv_coro PUBLIC ${ASAN_LINK_FLAG})
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

set(CPACK_PACKAGE_VENDOR "https://github.com/zelang-dev/uv_coroutine")
set(CPACK_PACKAGE_VERSION 1.0.0)
include(CPack)

set(CMAKE_INSTALL_CONFIG_NAME ${CMAKE_BUILD_TYPE})
install(TARGETS ${uv_coro} DESTINATION lib)
install(DIRECTORY include/ DESTINATION include)

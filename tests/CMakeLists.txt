cmake_minimum_required(VERSION 3.11...3.14)

set(TARGET_LIST
 test-fs
 test-fs_open
 test-fs_watch
 test-dns
 test-stream
 test-tcp
 test-tls
 test-udp
 test-pipe
 test-spawn
 test-queue_work
)

add_executable(child child.c)
target_link_libraries(child asio)

foreach (TARGET ${TARGET_LIST})
    add_executable(${TARGET} ${TARGET}.c )
    target_link_libraries(${TARGET} asio)
    add_test(NAME ${TARGET} COMMAND ${TARGET} WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
endforeach()

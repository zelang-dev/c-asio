cmake_minimum_required(VERSION 3.11...3.14)

if(WIN32)
	add_definitions("/wd4477")
endif()

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
target_link_libraries(child ${PROJECT_NAME})

add_executable(client client.c)
target_link_libraries(client ${PROJECT_NAME})

foreach (TARGET ${TARGET_LIST})
    add_executable(${TARGET} ${TARGET}.c )
    target_link_libraries(${TARGET} ${PROJECT_NAME})
    add_test(NAME ${TARGET} COMMAND ${TARGET} WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
endforeach()

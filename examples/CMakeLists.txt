cmake_minimum_required(VERSION 2.8...3.14)

add_subdirectory(echo-server)

set(TARGET_LIST helloworld spawn tcp-echo-server uvcat uvtee onchange progress queue-cancel queue-work dns)
foreach (TARGET ${TARGET_LIST})
    add_executable(${TARGET} ${TARGET}.c)
    target_link_libraries(${TARGET} uv_coro)
endforeach()

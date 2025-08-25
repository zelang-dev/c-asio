cmake_minimum_required(VERSION 2.8...3.14)

set(TARGET_LIST
 helloworld
 spawn
 tcp-echo-server
 uvcat
 uvtee
 onchange
 progress
 queue-cancel
 queue-work
 dns
 create-x509
 uv_tls_server
 uv_tls_client
 waitgroup_work
)

foreach (TARGET ${TARGET_LIST})
    add_executable(${TARGET} ${TARGET}.c)
    target_link_libraries(${TARGET} asio)
endforeach()

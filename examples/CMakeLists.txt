add_subdirectory(evt_tls)

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
 waitgroup_work
)

foreach (TARGET ${TARGET_LIST})
    add_executable(${TARGET} ${TARGET}.c)
    target_link_libraries(${TARGET} asio)
endforeach()

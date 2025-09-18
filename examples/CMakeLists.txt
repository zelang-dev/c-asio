
set(TARGET_LIST
 helloworld
 spawn
 tcp-echo-server
 fetch
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

file(COPY ../cert.pem DESTINATION ${CMAKE_BINARY_DIR})

foreach (TARGET ${TARGET_LIST})
    add_executable(${TARGET} ${TARGET}.c)
    target_link_libraries(${TARGET} ${PROJECT_NAME})
endforeach()

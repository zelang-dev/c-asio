add_library(evt_tls STATIC src/evt_tls.c)
target_link_libraries(evt_tls PUBLIC asio)

add_executable(uv_tls_server uv_tls_server.c)
target_link_libraries(uv_tls_server evt_tls)

add_executable(uv_tls_client uv_tls_client.c)
target_link_libraries(uv_tls_client evt_tls)

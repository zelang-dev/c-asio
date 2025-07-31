cmake_minimum_required(VERSION 2.8...3.14)
project(uv-tls-examples)

add_executable(test_tls test_tls.c)
add_executable(test_tls_client test_tls_client.c)
add_executable(create-x509 create-x509.c applink.c)

target_link_libraries(test_tls asio)
target_link_libraries(test_tls_client asio)
target_link_libraries(create-x509 asio)

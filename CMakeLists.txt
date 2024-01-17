cmake_minimum_required(VERSION 3.25)
project(eTPSS C)

set(CMAKE_C_STANDARD 11)

#定义两个变量，表示头文件路径和库路径
find_package(OpenSSL REQUIRED)

if(OPENSSL_FOUND)

    add_executable(${PROJECT_NAME} eTPSS_test.c eTPSS.c)

    target_include_directories(${PROJECT_NAME} PUBLIC include)
    # 链接 OpenSSL 库
    target_link_libraries(${PROJECT_NAME} OpenSSL::SSL OpenSSL::Crypto)

endif (OPENSSL_FOUND)

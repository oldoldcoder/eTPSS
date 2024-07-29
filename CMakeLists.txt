cmake_minimum_required(VERSION 3.28)
project(eTPSS CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")
#定义两个变量，表示头文件路径和库路径
find_package(OpenSSL REQUIRED)

# 添加源文件目录
aux_source_directory(include SOURCE_FILES)
aux_source_directory(test SOURCE_FILES)
# 显示的包含头文件
include_directories(include)

if(OPENSSL_FOUND)
    add_executable(${PROJECT_NAME} ${SOURCE_FILES} include/eTPSS.cpp)

    add_executable(eTPSS_test ${SOURCE_FILES} include/eTPSS.cpp)

    target_include_directories(${PROJECT_NAME} PUBLIC include)
    target_include_directories(eTPSS_test PUBLIC include)
    # 链接 OpenSSL 库
    target_link_libraries(${PROJECT_NAME} OpenSSL::SSL OpenSSL::Crypto)
    target_link_libraries(eTPSS_test OpenSSL::SSL OpenSSL::Crypto)

endif (OPENSSL_FOUND)
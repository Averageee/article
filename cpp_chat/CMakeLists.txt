cmake_minimum_required(VERSION 3.15)
project(CppChat LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 查找Boost库
find_package(Boost 1.70 REQUIRED COMPONENTS system)

# 创建服务器可执行文件
add_executable(server src/server.cpp)
target_link_libraries(server PRIVATE Boost::system)

# 创建客户端可执行文件
add_executable(client src/client.cpp)
target_link_libraries(client PRIVATE Boost::system)

# 设置输出目录
set_target_properties(server client PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)

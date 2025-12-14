cmake_minimum_required(VERSION 3.12)

project(test)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(${PROJECT_NAME} main.cpp)
target_include_directories(${PROJECT_NAME} PUBLIC "/usr/local/include")

# 只保留这一行，删除其他target_link_libraries调用
target_link_libraries(${PROJECT_NAME} PUBLIC 
    "/usr/local/lib/libntl.a"
    "/usr/lib/x86_64-linux-gnu/libgmp.a"
    crypto
)

cmake_minimum_required(VERSION 3.16)
project(ThresholdPRFBoost)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 查找需要的包
find_package(Boost REQUIRED COMPONENTS system)
find_package(OpenSSL REQUIRED)

# 检查是否找到依赖
if(NOT Boost_FOUND)
    message(FATAL_ERROR "Boost not found. Please install libboost-all-dev")
endif()

if(NOT OPENSSL_FOUND)
    message(FATAL_ERROR "OpenSSL not found. Please install libssl-dev")
endif()

# 定义库文件路径
set(NTL_LIBRARY "/usr/local/lib/libntl.a")
set(GMP_LIBRARY "/usr/lib/x86_64-linux-gnu/libgmp.a")


# 检查库文件是否存在
if(NOT EXISTS ${NTL_LIBRARY})
    message(FATAL_ERROR "NTL library not found at ${NTL_LIBRARY}. Please install libntl-dev")
endif()

if(NOT EXISTS ${GMP_LIBRARY})
    message(FATAL_ERROR "GMP library not found at ${GMP_LIBRARY}. Please install libgmp-dev")
endif()

# 编译标志
add_compile_options(-Wall -Wextra -O2)

# 用户端可执行文件
add_executable(user_main user/user_main.cpp)

# 为每个目标单独设置包含目录
target_include_directories(user_main PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${Boost_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
    "/usr/local/include"
)

target_link_libraries(user_main
    ${Boost_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${NTL_LIBRARY}
    ${GMP_LIBRARY}
    pthread
)

# 服务器端可执行文件
add_executable(server_main server/server_main.cpp)

target_include_directories(server_main PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${Boost_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
    "/usr/local/include"
)

target_link_libraries(server_main
    ${Boost_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${NTL_LIBRARY}
    ${GMP_LIBRARY}
    pthread
)
# 设备端可执行文件
add_executable(device_main device/device_main.cpp)

target_include_directories(device_main PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${Boost_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
    "/usr/local/include"
)

target_link_libraries(device_main
    ${Boost_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${NTL_LIBRARY}
    ${GMP_LIBRARY}
    pthread
)

# 显示配置信息
message(STATUS "Configuration Summary:")
message(STATUS "  Source dir: ${CMAKE_SOURCE_DIR}")
message(STATUS "  Boost version: ${Boost_VERSION}")
message(STATUS "  Boost libraries: ${Boost_LIBRARIES}")
message(STATUS "  OpenSSL version: ${OPENSSL_VERSION}")
message(STATUS "  NTL library: ${NTL_LIBRARY}")
message(STATUS "  GMP library: ${GMP_LIBRARY}")

# 安装规则
install(TARGETS user_main server_main device_main
    RUNTIME DESTINATION bin
)


cmake_minimum_required(VERSION 3.12)

project(test)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# include_directories("F:\\arttcle_tools\\WinNTL-11_5_1\\include")
# find_package(NTL REQUIRED)

add_executable(${PROJECT_NAME} main.cpp)
target_include_directories(${PROJECT_NAME} PUBLIC "/usr/local/include") #NTL .h
#target_include_directories(${PROJECT_NAME} PUBLIC "/usr/local/include") #GMP .h

target_link_libraries(${PROJECT_NAME} PUBLIC "/usr/local/lib/libntl.a") # NTL .a
target_link_libraries(${PROJECT_NAME} PUBLIC "/usr/lib/x86_64-linux-gnu/libgmp.a") # GMP .a 
# target_link_libraries(your_target PUBLIC 
#     NTL::NTL
# )
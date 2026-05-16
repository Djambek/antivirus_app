cmake_minimum_required(VERSION 3.15)
project(TrayApp VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_executable(TrayApp WIN32 main.cpp resource.rc)

target_compile_definitions(TrayApp PRIVATE UNICODE _UNICODE)

target_link_libraries(TrayApp PRIVATE user32 shell32)
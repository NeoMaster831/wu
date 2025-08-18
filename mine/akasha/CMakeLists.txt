cmake_minimum_required(VERSION 3.22)

project(akasha LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(${PROJECT_NAME} src/main.cpp)
target_compile_options(${PROJECT_NAME} PRIVATE -O3 -march=native -Wno-terminate)
target_link_options(${PROJECT_NAME} PRIVATE -static -static-libgcc -static-libstdc++ -Wl,--wrap=_ZN9__gnu_cxx27__verbose_terminate_handlerEv)
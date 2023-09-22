cmake_minimum_required(VERSION 3.24)

project(discordbot++)

include(FetchContent)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}")
set(BUILD_SHARED_LIBS ON CACHE INTERNAL "Build SHARED libraries")

FetchContent_Declare(
  simdjson
  GIT_REPOSITORY https://github.com/simdjson/simdjson.git
  GIT_SHALLOW TRUE)
FetchContent_MakeAvailable(simdjson)

find_package(OpenSSL REQUIRED)

add_executable(discordbot++ main.cpp)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_definitions(discordbot++ PUBLIC LOG)
    if(MSVC) # MSVC(Visual Studio) Compiler
        set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreadedDebugDLL")
        target_compile_options(discordbot++ PUBLIC /Od /std:c++17)
    else() # gcc or clang
        target_compile_options(discordbot++ PUBLIC -O0 -std=c++17)
    endif()
else()
    if(MSVC)
        set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreadedDLL")
        target_compile_options(discordbot++ PUBLIC /O2 /std:c++17)
    else()
        target_compile_options(discordbot++ PUBLIC -O3 -std=c++17)
    endif()
endif()

target_link_libraries(discordbot++ simdjson OpenSSL::SSL OpenSSL::Crypto)

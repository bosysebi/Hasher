cmake_minimum_required(VERSION 3.0)

# Project configuration
project(hw04)
set(SOURCES     gethash.c)
set(EXECUTABLE  hash)
set(MVM_SRC 	hash_helper.c)

# Executable
add_library(mvm STATIC ${MVM_SRC})
add_executable(${EXECUTABLE} ${SOURCES})

target_link_libraries(${EXECUTABLE} mvm)

# Configure compiler warnings
if (CMAKE_C_COMPILER_ID MATCHES Clang OR ${CMAKE_C_COMPILER_ID} STREQUAL GNU)
  # using regular Clang, AppleClang or GCC
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -Wall -Wextra -pedantic")
elseif (${CMAKE_C_COMPILER_ID} STREQUAL MSVC)
  # using Visual Studio C++
  target_compile_definitions(${EXECUTABLE} PRIVATE _CRT_SECURE_NO_DEPRECATE)
  set(CMAKE_CXX_FLAGS "/permissive- /W4 /EHsc")
endif()

if(MINGW)
    target_compile_definitions(${EXECUTABLE} PRIVATE __USE_MINGW_ANSI_STDIO=1)
endif()

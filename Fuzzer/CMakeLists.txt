﻿# CMakeList.txt : CMake project for Fuzzer, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)


# Add source to this project's executable.
#add_executable (Fuzzer "Fuzzer.cpp" "Fuzzer.h")
add_executable (${PROJECT_NAME} "Fuzzer.cpp" "Fuzzer.h")
# TODO: Add tests and install targets if needed.

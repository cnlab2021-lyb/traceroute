cmake_minimum_required(VERSION 3.15)
project(traceroute)

add_executable(traceroute traceroute.cpp)
target_compile_features(traceroute PRIVATE cxx_std_17)

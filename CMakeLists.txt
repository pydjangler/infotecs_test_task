cmake_minimum_required(VERSION 3.26)
project(package_classification)

set(CMAKE_CXX_STANDARD 17)

add_executable(package_classification main.cpp
        PackageClassifier.h
        PackageClass.cpp)

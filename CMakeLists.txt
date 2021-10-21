# CMakeList.txt: 顶层 CMake 项目文件，在此处执行全局配置
# 并包含子项目。
#
cmake_minimum_required (VERSION 3.8)

project ("gmssl-v3-gm-namespace")

# 包含子项目。
add_subdirectory ("gmssl-v3-dev-main")
add_subdirectory ("gm")
add_subdirectory ("test")
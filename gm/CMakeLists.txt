# CMakeList.txt: gm 的 CMake 项目，在此处包括源代码并定义
# 项目特定的逻辑。
# 封装gm库，暴露sm3、sm4接口

cmake_minimum_required (VERSION 3.8)

include_directories(${CMAKE_SOURCE_DIR}/gmssl-v3-dev-main/include)

# 将源代码添加到此项目的可执行文件。
add_library(gm SHARED "gm.cpp" "gm.h")

target_link_libraries( gm PRIVATE gmsslpp)

# TODO: 如有需要，请添加测试并安装目标。

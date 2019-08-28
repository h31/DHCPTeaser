cmake_minimum_required(VERSION 3.14)
project(DHCPTeaser C)

set(CMAKE_C_STANDARD 99)

add_executable(DHCPTeaser main.c dhcp.c net.c)
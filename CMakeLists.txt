cmake_minimum_required (VERSION 2.6)

project (mysql_sniffer)

INCLUDE_DIRECTORIES(/usr/include ${PROJECT_SOURCE_DIR}/include/)
LINK_DIRECTORIES(${PROJECT_SOURCE_DIR}/lib/)

ADD_SUBDIRECTORY(src bin)

#SET(CMAKE_VERBOSE_MAKEFILE ON)
SET(CMAKE_INSTALL_PREFIX /usr/local)



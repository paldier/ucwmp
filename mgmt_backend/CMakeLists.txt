cmake_minimum_required(VERSION 2.6)

INCLUDE(CheckIncludeFiles)

PROJECT(ucwmp C)
ADD_DEFINITIONS(-Os -Wall -Werror --std=gnu99 -g3 -Wmissing-declarations)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

IF(APPLE)
  INCLUDE_DIRECTORIES(/opt/local/include)
  LINK_DIRECTORIES(/opt/local/lib)
  SET(DUMMY_MODE 1)
ENDIF()

IF(DUMMY_MODE)
  ADD_DEFINITIONS(-DDUMMY_MODE=1)
ENDIF()

ADD_EXECUTABLE(backend-test test.c)
ADD_LIBRARY(mgmt_backend STATIC parse.c)

find_library(json NAMES json-c json)
TARGET_LINK_LIBRARIES(mgmt_backend ubus ubox blobmsg_json ${json})
TARGET_LINK_LIBRARIES(backend-test mgmt_backend)
TARGET_LINK_LIBRARIES(backend-test mgmt_backend)

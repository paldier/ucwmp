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

ADD_EXECUTABLE(session session.c session-rpc.c session-soap.c session-builtin.c object.c)
ADD_EXECUTABLE(cwmpd main.c state.c ubus.c)

find_library(json NAMES json-c json)
TARGET_LINK_LIBRARIES(session ubus uclient ubox roxml blobmsg_json ${json})
TARGET_LINK_LIBRARIES(cwmpd uci ubus ubox blobmsg_json ${json})

INSTALL(TARGETS session
	RUNTIME DESTINATION bin
	LIBRARY DESTINATION lib
)

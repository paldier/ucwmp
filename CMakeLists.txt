cmake_minimum_required(VERSION 2.6)

INCLUDE(CheckIncludeFiles)

PROJECT(ucwmp C)
ADD_DEFINITIONS(-Os -Wall -Werror --std=gnu99 -g3 -Wmissing-declarations -I${CMAKE_SOURCE_DIR})

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

IF(APPLE)
  INCLUDE_DIRECTORIES(/opt/local/include)
  LINK_DIRECTORIES(/opt/local/lib)
  SET(DUMMY_MODE 1)
ENDIF()

IF(DUMMY_MODE)
  ADD_DEFINITIONS(-DDUMMY_MODE=1)
ENDIF()

ADD_EXECUTABLE(cwmp-session
	session/main.c session/rpc.c session/soap.c session/attr.c
	session/builtin.c session/object.c session/backend.c)

ADD_EXECUTABLE(cwmpd main.c state.c ubus.c download.c cache.c)
ADD_EXECUTABLE(connreq connreq.c)

find_library(json NAMES json-c json)
TARGET_LINK_LIBRARIES(cwmp-session ubus uclient ubox roxml blobmsg_json ${json} acs)
TARGET_LINK_LIBRARIES(cwmpd uci uclient ubus ubox blobmsg_json ${json})
TARGET_LINK_LIBRARIES(connreq ubus ubox)

INSTALL(TARGETS cwmp-session cwmpd
	RUNTIME DESTINATION sbin
	LIBRARY DESTINATION lib
)
INSTALL(TARGETS connreq
	RUNTIME DESTINATION libexec/cwmp
)

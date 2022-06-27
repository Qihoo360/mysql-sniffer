SET(CMAKE_C_FLAGS "-DENABLE_TCPREASM -O3 -Wall -std=gnu99 ")
SET(CMAKE_CXX_FLAGS "-DENABLE_TCPREASM -O3 -Wall ")
SET(CMAKE_BUILD_TYPE "Release")
#SET(CMAKE_BUILD_TYPE "Debug")

SET(CMAKE_C_FLAGS_RELEASE "-DENABLE_TCPREASM -O2")
SET(CMAKE_CXX_FLAGS_RELEASE "-DENABLE_TCPREASM -O2")

#SET(CMAKE_C_FLAGS_DEBUG "${TCPREASM} -DENABLE_DETECT_FILE_STALE -g -ggdb")
#SET(CMAKE_CXX_FLAGS_DEBUG "${TCPREASM} -DENABLE_DETECT_FILE_STALE -g -ggdb")

# use "cmake -DCMAKE_BUILD_TYPE=Debug" to use Debug options, and annotate the SET(CMAKE_BUILD_TYPE "Release")
SET(CMAKE_C_FLAGS_DEBUG "-DDEBUG -DENABLE_TCPREASM -g3 -O0 -std=gnu99 ")
SET(CMAKE_CXX_FLAGS_DEBUG "-DDEBUG -DENABLE_TCPREASM -g3 -O0 ")

SET(SRC_LIST main.c
    mysql-dissector.c
    util.c
    session.cpp
    sniff-config.cpp
    sniff-log.cpp
    )

# make libnids-1.24
EXECUTE_PROCESS(COMMAND make clean
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/libnids-1.24/src)

EXECUTE_PROCESS(COMMAND make
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/libnids-1.24/src)

ADD_EXECUTABLE(mysql-sniffer ${SRC_LIST})
TARGET_LINK_LIBRARIES(mysql-sniffer optimized
    libnidstcpreasm.a
    libpthread.so.0
    libnet.a 
    libpcap.a
    libglib-2.0.a 
    libgthread-2.0.a
    librt.so)
   
TARGET_LINK_LIBRARIES(mysql-sniffer debug
    libnidstcpreasm-dbg.a
    libpthread.so.0
    libnet.a 
    libpcap.a
    libglib-2.0.a
    libgthread-2.0.a
    librt.so)


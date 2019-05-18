project(GuomiLib)
cmake_minimum_required(VERSION 2.8)
include_directories(${PROJECT_SOURCE_DIR}/src)

add_library(SM2 ${PROJECT_SOURCE_DIR}/src/sm2/sm2.c ${PROJECT_SOURCE_DIR}/src/sm2/sm2.h)
add_library(SM3 ${PROJECT_SOURCE_DIR}/src/sm3/sm3.c ${PROJECT_SOURCE_DIR}/src/sm3/sm3.h ${PROJECT_SOURCE_DIR}/src/sm3/sm3_locl.h)
add_library(SM4 ${PROJECT_SOURCE_DIR}/src/sm4/sm4.c ${PROJECT_SOURCE_DIR}/src/sm4/sm4.h)

add_executable(GuomiLib ${PROJECT_SOURCE_DIR}/src/main.cpp ${PROJECT_SOURCE_DIR}/src/gmsm2.cpp ${PROJECT_SOURCE_DIR}/src/gmsm2.h
        ${PROJECT_SOURCE_DIR}/src/gmsm3.cpp ${PROJECT_SOURCE_DIR}/src/gmsm3.h ${PROJECT_SOURCE_DIR}/src/gmsm4.cpp ${PROJECT_SOURCE_DIR}/src/gmsm4.h)
target_link_libraries(GuomiLib SM2)
target_link_libraries(GuomiLib SM3)
target_link_libraries(GuomiLib SM4)
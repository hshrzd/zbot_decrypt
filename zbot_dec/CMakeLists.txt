cmake_minimum_required (VERSION 2.8)

# replace "project_template" by your own project name:
project ( zbot_dec )

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

include_directories ( ${PARAMKIT_DIR}/include )

set (srcs
	zbot_common.cpp
	util.cpp
)

# general headers - they will be used for both EXE and DLL:
set (hdrs
	zbot_common.h
	util.h
)

set (rsrc
#put your resources here
)


# DLL-specific headers - they will be included only in the DLL build:
set (dll_hdrs
#put your headers here
)

add_executable ( ${PROJECT_NAME} ${exe_hdrs} ${srcs} ${rsrc} main.cpp )

# link with paramkit.lib
target_link_libraries ( ${PROJECT_NAME} ${PARAMKIT_LIB} )

#dependencies:
add_dependencies( ${PROJECT_NAME} paramkit )

INSTALL( TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX} COMPONENT ${PROJECT_NAME} )

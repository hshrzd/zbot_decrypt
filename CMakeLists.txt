cmake_minimum_required ( VERSION 2.8 )

# replace "peconv_project" by your own project name:
project ( zbot_decrypt )

# libs
# modules:
set ( M_PARSER "libpeconv/libpeconv" )

# modules paths:
set (PECONV_DIR "${CMAKE_SOURCE_DIR}/${M_PARSER}" CACHE PATH "PEConv main path")
set ( M_PARAMKIT "paramkit/paramkit" )

# modules paths:
set (PARAMKIT_DIR "${CMAKE_SOURCE_DIR}/${M_PARAMKIT}" CACHE PATH "ParamKit main path")
add_subdirectory ( ${PARAMKIT_DIR} )
set ( PARAMKIT_LIB $<TARGET_FILE:paramkit> CACHE PATH "ParamKit library path" )

# Add sub-directories
#
add_subdirectory ( zbot_dec )

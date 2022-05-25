cmake_minimum_required(VERSION 3.10)
project(ocelot C)

set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")
find_package(LibClang REQUIRED)

set(SOURCE src/ocelot.c src/ocelot.h)

option(OCELOT_ENABLE_JSON "Enable `ocelot_json_serialize` and `ocelot_json_parse`" ON)
if (OCELOT_ENABLE_JSON)
	add_compile_definitions(OCELOT_ENABLE_JSON)
	add_executable(ocelot_bin src/ocelot-cli.c ${SOURCE})
	target_include_directories(ocelot_bin PUBLIC ${LIBCLANG_INCLUDE_DIRS})
	target_link_libraries(ocelot_bin ${LIBCLANG_LIBRARIES})
	set_target_properties(ocelot_bin PROPERTIES OUTPUT_NAME ocelot)
endif()

add_library(ocelot SHARED ${SOURCE})
target_include_directories(ocelot PUBLIC ${LIBCLANG_INCLUDE_DIRS})
target_link_libraries(ocelot ${LIBCLANG_LIBRARIES})

add_library(ocelot_static STATIC ${SOURCE})
target_include_directories(ocelot_static PUBLIC ${LIBCLANG_INCLUDE_DIRS})
target_link_libraries(ocelot_static ${LIBCLANG_LIBRARIES})

file(GLOB_RECURSE sources
    RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    CONFIGURE_DEPENDS
    "*.c")

list(REMOVE_ITEM sources dlp_main.c)

add_executable(${PROJECT_NAME} dlp_main.c)
add_library(${PROJECT_NAME}_static STATIC ${sources})
target_link_libraries(${PROJECT_NAME}_static ${PROJECT_NAME}_resource_static)
target_link_libraries(${PROJECT_NAME} ${PROJECT_NAME}_static)

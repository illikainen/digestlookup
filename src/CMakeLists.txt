file(GLOB_RECURSE sources
    RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    CONFIGURE_DEPENDS
    "*.c")

list(REMOVE_ITEM sources dlp_main.c)

add_library(${PROJECT_NAME}_obj OBJECT ${sources})
target_link_libraries(${PROJECT_NAME}_obj ${PROJECT_NAME}_resource_static)

add_executable(${PROJECT_NAME} dlp_main.c)
target_link_libraries(${PROJECT_NAME} ${PROJECT_NAME}_obj)

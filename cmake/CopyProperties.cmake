# See:
# - https://gitlab.kitware.com/cmake/cmake/-/issues/14778
# - https://gitlab.kitware.com/cmake/cmake/-/issues/18010
# - https://gitlab.kitware.com/cmake/cmake/-/issues/18090
function(copy_properties dst scope src)
    target_include_directories(${dst} ${scope}
        $<TARGET_PROPERTY:${src},INTERFACE_INCLUDE_DIRECTORIES>)
    target_compile_definitions(${dst} ${scope}
        $<TARGET_PROPERTY:${src},INTERFACE_COMPILE_DEFINITIONS>)
    target_compile_options(${dst} ${scope}
        $<TARGET_PROPERTY:${src},INTERFACE_COMPILE_OPTIONS>)
    target_link_options(${dst} ${scope}
        $<TARGET_PROPERTY:${src},INTERFACE_LINK_OPTIONS>)
    target_link_libraries(${dst} ${scope}
        $<TARGET_PROPERTY:${src},INTERFACE_LINK_LIBRARIES>)
endfunction()

# Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
#
# SPDX-License-Identifier:

include(AddResource)

add_resource(
    "${CMAKE_CURRENT_SOURCE_DIR}/dlp.gresource.xml"
    STATIC "${PROJECT_NAME}_resource_static"
    INTERNAL
)

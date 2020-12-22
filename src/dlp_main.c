/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#include "dlp_cli.h"

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    return !dlp_cli(argc, argv);
}

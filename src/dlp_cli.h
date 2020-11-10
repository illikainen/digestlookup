/*
 * Copyright (c) 2020 Hans Jerry Illikainen <hji@dyntopia.com>
 *
 * SPDX-License-Identifier:
 */

#ifndef DLP_CLI_H
#define DLP_CLI_H

#include <errno.h>

#include "config.h"
#include "dlp.h"

errno_t dlp_cli(void) DLP_NODISCARD;

#endif /* DLP_CLI_H */

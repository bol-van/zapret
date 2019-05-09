#pragma once

#include <stdio.h>
#include <zlib.h>

int z_readfile(FILE *F,char **buf,size_t *size);

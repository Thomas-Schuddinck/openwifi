// Author:		Thomas Schuddinck
// Year:		2022

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <getopt.h>

typedef unsigned char u8;

static const u8 bits_to_rates[16] = {0, 48, 0, 54, 0, 12, 0, 18, 0, 24, 0, 36, 0, 6, 0, 9};
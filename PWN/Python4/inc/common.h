#pragma once
#ifndef __COMMON_H
#define __COMMON_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define NELEM(A) (sizeof(A) / sizeof((A)[0]))
#define MIN(A, B) (((A) < (B)) ? (A) : (B))
#define SIZEOF_MEMBER(type, member) (sizeof(((type *)0)->member))

#endif /* __COMMON_H */

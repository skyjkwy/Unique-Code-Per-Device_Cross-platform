#ifndef GENERATOR_VERSION_H
#define GENERATOR_VERSION_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

extern const int GEN_VERSION_MAJOR;
extern const int GEN_VERSION_MINOR;
extern const int GEN_VERSION_BUILD;
extern const int GEN_VERSION_REVISION;

extern const char GEN_VERSION_STRING[];
extern const wchar_t GEN_VERSION_STRING_W[];

#ifdef __cplusplus
}
#endif

#endif

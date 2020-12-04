/*
  Common code for Gust (Koei/Tecmo) PC games tools
  Copyright © 2019-2020 VitaSmith

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifdef _DEBUG
#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>
#endif

#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>

#pragma once

#define _STRINGIFY(x) #x
#define STRINGIFY(x) _STRINGIFY(x)

#ifndef APP_VERSION
#define APP_VERSION_STR "[DEV VERSION]"
#else
#define APP_VERSION_STR STRINGIFY(APP_VERSION)
#endif

#if defined(_WIN32)
#include <windows.h>
#define ftell64 _ftelli64
#define fseek64 _fseeki64
#if !defined(S_ISDIR)
#define S_ISDIR(ST_MODE) (((ST_MODE) & _S_IFMT) == _S_IFDIR)
#endif
#if !defined(S_ISREG)
#define S_ISREG(ST_MODE) (((ST_MODE) & _S_IFMT) == _S_IFREG)
#endif
#define CREATE_DIR(path) CreateDirectoryA(path, NULL)
#define PATH_SEP '\\'
#else
#define ftell64 ftello64
#define fseek64 fseeko64
#define CREATE_DIR(path) (mkdir(path, 0755) == 0)
#define PATH_SEP '/'
#endif

#ifndef min
#define min(a,b) (((a) < (b)) ? (a) : (b))
#endif

#ifndef max
#define max(a,b) (((a) > (b)) ? (a) : (b))
#endif

#ifndef array_size
#define array_size(a) (sizeof(a) / sizeof(*a))
#endif

#ifndef is_power_of_2
#define is_power_of_2(x) (((x) & ((x) - 1)) == 0)
#endif

#if defined(_WIN32)
static __inline char* _basename(const char* path, bool remove_extension)
{
    static char basename[128];
    static char ext[64];
    ext[0] = 0;
    _splitpath_s(path, NULL, 0, NULL, 0, basename, sizeof(basename), ext, sizeof(ext));
    if ((ext[0] != 0) && !remove_extension)
        strncat(basename, ext, sizeof(basename) - strlen(basename));
    return basename;
}
#define basename(path) _basename(path, false)
#define appname(path) _basename(path, true)
#else
#define appname(path) basename(path)
#endif

#if defined (_MSC_VER)
#include <stdlib.h>
#define bswap_uint16 _byteswap_ushort
#define bswap_uint32 _byteswap_ulong
#define bswap_uint64 _byteswap_uint64
#else
#define bswap_uint16 __builtin_bswap16
#define bswap_uint32 __builtin_bswap32
#define bswap_uint64 __builtin_bswap64
#endif

// Returns the position of the msb. v should be nonzero
static __inline uint32_t find_msb(uint32_t v)
{
#if defined (_MSC_VER)
    DWORD pos;
    _BitScanReverse(&pos, v);
    return pos;
#else
    return 31- __builtin_clz(v);
#endif
}

static __inline uint16_t getle16(const void* p)
{
    return *(const uint16_t*)(const uint8_t*)(p);
}

static __inline void setle16(const void* p, const uint16_t v)
{
    *((uint16_t*)p) = v;
}

static __inline uint16_t getbe16(const void* p)
{
    return bswap_uint16(getle16(p));
}

static __inline void setbe16(const void* p, const uint16_t v)
{
    setle16(p, bswap_uint16(v));
}

static __inline uint32_t getle24(const void* _p)
{
    uint8_t* p = (uint8_t*)_p;
    return p[0] | (p[1] << 8) | (p[2] << 16);
}

static __inline void setle24(const void* _p, const uint32_t v)
{
    uint8_t* p = (uint8_t*)_p;
    p[0] = v & 0xff;
    p[1] = (v >> 8) & 0xff;
    p[2] = (v >> 16) & 0xff;
}

static __inline uint32_t getbe24(const void* _p)
{
    uint8_t* p = (uint8_t*)_p;
    return (p[0] << 16) | (p[1] << 8) | p[2];
}

static __inline void setbe24(const void* _p, const uint32_t v)
{
    uint8_t* p = (uint8_t*)_p;
    p[0] = (v >> 16) & 0xff;
    p[1] = (v >> 8) & 0xff;
    p[2] = v & 0xff;
}

static __inline uint32_t getle32(const void* p)
{
    return *(const uint32_t*)(const uint8_t*)(p);
}

static __inline void setle32(const void* p, const uint32_t v)
{
    *((uint32_t*)p) = v;
}

static __inline uint32_t getbe32(const void* p)
{
    return bswap_uint32(getle32(p));
}

static __inline void setbe32(const void* p, const uint32_t v)
{
    setle32(p, bswap_uint32(v));
}

static __inline uint64_t getle64(const void* p)
{
    return *(const uint64_t*)(const uint8_t*)(p);
}

static __inline void setle64(const void* p, const uint64_t v)
{
    *((uint64_t*)p) = v;
}
static __inline uint64_t getbe64(const void* p)
{
    return bswap_uint64(getle64(p));
}

static __inline void setbe64(const void* p, const uint64_t v)
{
    setle64(p, bswap_uint64(v));
}

bool create_path(char* path);
char* change_extension(const char* path, const char* extension);
size_t get_trailing_slash(const char* path);

bool is_file(const char* path);
bool is_directory(const char* path);

uint32_t read_file(const char* path, uint8_t** buf);
void create_backup(const char* path);
bool write_file(const uint8_t* buf, const uint32_t size, const char* path, const bool backup);

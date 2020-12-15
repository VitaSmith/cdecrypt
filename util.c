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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utf8.h"
#include "util.h"

bool create_path(char* path)
{
    bool result = true;
    struct stat64_t st;
    if (stat64_utf8(path, &st) != 0) {
        // Directory doesn't exist, create it
        size_t pos = 0;
        for (size_t n = strlen(path); n > 0; n--) {
            if (path[n] == PATH_SEP) {
                pos = n;
                break;
            }
        }
        if (pos > 0) {
            // Create parent dirs
            path[pos] = 0;
            char* new_path = malloc(strlen(path) + 1);
            if (new_path == NULL) {
                fprintf(stderr, "ERROR: Can't allocate path\n");
                return false;
            }
            strcpy(new_path, path);
            result = create_path(new_path);
            free(new_path);
            path[pos] = PATH_SEP;
        }
        // Create node
        if (result)
            result = CREATE_DIR(path);
    } else if (!S_ISDIR(st.st_mode)) {
        fprintf(stderr, "ERROR: '%s' exists but isn't a directory\n", path);
        return false;
    }

    return result;
}

bool is_file(const char* path)
{
    struct stat64_t st;
    return (stat64_utf8(path, &st) == 0) && S_ISREG(st.st_mode);
}

bool is_directory(const char* path)
{
    struct stat64_t st;
    return (stat64_utf8(path, &st) == 0) && S_ISDIR(st.st_mode);
}

char* change_extension(const char* path, const char* extension)
{
    static char new_path[PATH_MAX];
    strncpy(new_path, basename((char*)path), sizeof(new_path) - 1);
    for (size_t i = 0; i < sizeof(new_path); i++) {
        if (new_path[i] == '.')
            new_path[i] = 0;
    }
    strncat(new_path, extension, sizeof(new_path) - strlen(new_path) - 1);
    return new_path;
}

size_t get_trailing_slash(const char* path)
{
    size_t i;
    if ((path == NULL) || (path[0] == 0))
        return 0;
    for (i = strlen(path) - 1; (i > 0) && ((path[i] != '/') && (path[i] != '\\')); i--);
    return (i == 0) ? 0: i + 1;
}

uint32_t read_file_max(const char* path, uint8_t** buf, uint32_t max_size)
{
    FILE* file = fopen_utf8(path, "rb");
    if (file == NULL) {
        fprintf(stderr, "ERROR: Can't open '%s'\n", path);
        return 0;
    }

    fseek(file, 0L, SEEK_END);
    uint32_t size = (uint32_t)ftell(file);
    fseek(file, 0L, SEEK_SET);
    if (max_size != 0)
        size = min(size, max_size);

    *buf = calloc(size, 1);
    if (*buf == NULL) {
        size = 0;
        goto out;
    }
    if (fread(*buf, 1, size, file) != size) {
        fprintf(stderr, "ERROR: Can't read '%s'\n", path);
        size = 0;
    }
out:
    fclose(file);
    if (size == 0) {
        free(*buf);
        *buf = NULL;
    }
    return size;
}

uint64_t get_file_size(const char* path)
{
    FILE* file = fopen_utf8(path, "rb");
    if (file == NULL) {
        fprintf(stderr, "ERROR: Can't open '%s'\n", path);
        return 0;
    }

    fseek(file, 0L, SEEK_END);
    uint64_t size = ftell64(file);
    fclose(file);
    return size;
}

void create_backup(const char* path)
{
    struct stat64_t st;
    if (stat64_utf8(path, &st) == 0) {
        char* backup_path = malloc(strlen(path) + 5);
        if (backup_path == NULL)
            return;
        strcpy(backup_path, path);
        strcat(backup_path, ".bak");
        if (stat64_utf8(backup_path, &st) != 0) {
            if (rename_utf8(path, backup_path) == 0)
                printf("Saved backup as '%s'\n", backup_path);
            else
                fprintf(stderr, "WARNING: Could not create backup file '%s\n", backup_path);
        }
        free(backup_path);
    }
}

bool write_file(const uint8_t* buf, const uint32_t size, const char* path, const bool backup)
{
    if (backup)
        create_backup(path);
    FILE* file = fopen_utf8(path, "wb");
    if (file == NULL) {
        fprintf(stderr, "ERROR: Can't create file '%s'\n", path);
        return false;
    }
    bool r = (fwrite(buf, 1, size, file) == size);
    fclose(file);
    if (!r)
        fprintf(stderr, "ERROR: Can't write file '%s'\n", path);
    return r;
}

/*
  cdecrypt - Decrypt Wii U NUS content files

  Copyright © 2013-2015 crediar <https://code.google.com/p/cdecrypt/>
  Copyright © 2020 VitaSmith <https://github.com/VitaSmith/cdecrypt>

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

#include <assert.h>
#include <direct.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl\aes.h>
//#include <openssl\sha.h>

#include "utf8.h"
#include "util.h"
#include "sha1.h"

#pragma comment(lib,"libcrypto.lib")

#define MAX_ENTRIES     90000
#define MAX_LEVELS      16
#define FST_MAGIC       ((uint32_t)'FST\0')

uint8_t WiiUCommonDevKey[16] =
    { 0x2F, 0x5C, 0x1B, 0x29, 0x44, 0xE7, 0xFD, 0x6F, 0xC3, 0x97, 0x96, 0x4B, 0x05, 0x76, 0x91, 0xFA };
uint8_t WiiUCommonKey[16] =
    { 0xD7, 0xB0, 0x04, 0x02, 0x65, 0x9B, 0xA2, 0xAB, 0xD2, 0xCB, 0x0D, 0xB2, 0x7F, 0xA2, 0xB6, 0x56 };

AES_KEY key;
uint8_t enc_title_key[16];
uint8_t dec_title_key[16];
uint8_t title_id[16];
uint8_t dkey[16];

uint64_t H0Count = 0;
uint64_t H0Fail  = 0;

#pragma pack(1)

enum ContentType
{
    CONTENT_REQUIRED = (1 << 0),    // not sure
    CONTENT_SHARED   = (1 << 15),
    CONTENT_OPTIONAL = (1 << 14),
};

typedef struct
{
    uint16_t IndexOffset;           //  0  0x204
    uint16_t CommandCount;          //  2  0x206
    uint8_t  SHA2[32];              //  12 0x208
} ContentInfo;

typedef struct
{
    uint32_t ID;                    //  0  0xB04
    uint16_t Index;                 //  4  0xB08
    uint16_t Type;                  //  6  0xB0A
    uint64_t Size;                  //  8  0xB0C
    uint8_t  SHA2[32];              //  16 0xB14
} Content;

typedef struct
{
    uint32_t SignatureType;         // 0x000
    uint8_t  Signature[0x100];      // 0x004

    uint8_t  Padding0[0x3C];        // 0x104
    uint8_t  Issuer[0x40];          // 0x140

    uint8_t  Version;               // 0x180
    uint8_t  CACRLVersion;          // 0x181
    uint8_t  SignerCRLVersion;      // 0x182
    uint8_t  Padding1;              // 0x183

    uint64_t SystemVersion;         // 0x184
    uint64_t TitleID;               // 0x18C
    uint32_t TitleType;             // 0x194
    uint16_t GroupID;               // 0x198
    uint8_t  Reserved[62];          // 0x19A
    uint32_t AccessRights;          // 0x1D8
    uint16_t TitleVersion;          // 0x1DC
    uint16_t ContentCount;          // 0x1DE
    uint16_t BootIndex;             // 0x1E0
    uint8_t  Padding3[2];           // 0x1E2
    uint8_t  SHA2[32];              // 0x1E4

    ContentInfo ContentInfos[64];

    Content  Contents[];            // 0x1E4

} TitleMetaData;

struct FSTInfo
{
    uint32_t Unknown;
    uint32_t Size;
    uint32_t UnknownB;
    uint32_t UnknownC[6];
};

struct FST
{
    uint32_t MagicBytes;
    uint32_t Unknown;
    uint32_t EntryCount;

    uint32_t UnknownB[5];

    struct FSTInfo FSTInfos[];
};

struct FEntry
{
    union
    {
        struct
        {
            uint32_t Type : 8;
            uint32_t NameOffset : 24;
        };
        uint32_t TypeName;
    };
    union
    {
        struct      // File Entry
        {
            uint32_t FileOffset;
            uint32_t FileLength;
        };
        struct       // Dir Entry
        {
            uint32_t ParentOffset;
            uint32_t NextOffset;
        };
        uint32_t entry[2];
    };
    uint16_t Flags;
    uint16_t ContentID;
};

static bool FileDump(const char* Name, void* Data, uint32_t Length)
{
    assert(Data != NULL);
    assert(Length != 0);

    FILE* Out = fopen_utf8(Name, "wb");
    if (Out == NULL) {
        fprintf(stderr, "ERROR: Cannot dump file \"%s\"\n", Name);
        return false;
    }

    bool r = (fwrite(Data, 1, Length, Out) == Length);
    if (!r)
        fprintf(stderr, "ERROR: Failed to dump file \"%s\"\n", Name);

    fclose(Out);
    return r;
}

static char ascii(char s)
{
    if (s < 0x20) return '.';
    if (s > 0x7E) return '.';
    return s;
}

static void hexdump(void* d, int32_t len)
{
    uint8_t* data;
    int32_t i, off;
    data = (uint8_t*)d;
    for (off = 0; off < len; off += 16) {
        printf("%08x  ", off);
        for (i = 0; i < 16; i++)
            if ((i + off) >= len)
                printf("   ");
            else
                printf("%02x ", data[off + i]);

        printf(" ");
        for (i = 0; i < 16; i++) {
            if ((i + off) >= len)
                printf(" ");
            else
                printf("%c", ascii(data[off + i]));
        }
        printf("\n");
    }
}

#define BLOCK_SIZE  0x10000
static bool ExtractFileHash(FILE* in, uint64_t PartDataOffset, uint64_t FileOffset, uint64_t Size, char* FileName, uint16_t ContentID)
{
    bool r = false;
    char *encdata = malloc(BLOCK_SIZE);
    char *decdata = malloc(BLOCK_SIZE);
    assert(encdata != NULL);
    assert(decdata != NULL);
    uint8_t IV[16];
    uint8_t hash[SHA_DIGEST_LENGTH];
    uint8_t H0[SHA_DIGEST_LENGTH];
    uint8_t Hashes[0x400];

    uint64_t Wrote = 0;
    uint64_t WriteSize = 0xFC00;	// Hash block size
    uint64_t Block = (FileOffset / 0xFC00) & 0xF;

    FILE* dst = fopen_utf8(FileName, "wb");
    if (dst == NULL) {
        fprintf(stderr, "ERROR: Could not create \"%s\"\n", FileName);
        goto out;
    }

    uint64_t roffset = FileOffset / 0xFC00 * BLOCK_SIZE;
    uint64_t soffset = FileOffset - (FileOffset / 0xFC00 * 0xFC00);

    if (soffset + Size > WriteSize)
        WriteSize = WriteSize - soffset;

    _fseeki64(in, PartDataOffset + roffset, SEEK_SET);
    while (Size > 0) {
        if (WriteSize > Size)
            WriteSize = Size;

        fread(encdata, sizeof(char), BLOCK_SIZE, in);

        memset(IV, 0, sizeof(IV));
        IV[1] = (uint8_t)ContentID;
        AES_cbc_encrypt((const uint8_t*)(encdata), (uint8_t*)Hashes, 0x400, &key, IV, AES_DECRYPT);

        memcpy(H0, Hashes + 0x14 * Block, SHA_DIGEST_LENGTH);

        memcpy(IV, Hashes + 0x14 * Block, sizeof(IV));
        if (Block == 0)
            IV[1] ^= ContentID;
        AES_cbc_encrypt((const uint8_t*)(encdata + 0x400), (uint8_t*)decdata, 0xFC00, &key, IV, AES_DECRYPT);


        sha1((const uint8_t*)decdata, 0xFC00, hash);
//        sha1(const uint8_t * input, size_t ilen, uint8_t output[SHA_DIGEST_LENGTH])

        if (Block == 0)
            hash[1] ^= ContentID;
        H0Count++;
        if (memcmp(hash, H0, SHA_DIGEST_LENGTH) != 0) {
            H0Fail++;
            hexdump(hash, SHA_DIGEST_LENGTH);
            hexdump(Hashes, 0x100);
            hexdump(decdata, 0x100);
            fprintf(stderr, "ERROR: Failed to verify H0 hash\n");
            goto out;
        }

        Size -= fwrite(decdata + soffset, sizeof(char), WriteSize, dst);

        Wrote += WriteSize;

        Block++;
        if (Block >= 16)
            Block = 0;

        if (soffset) {
            WriteSize = 0xFC00;
            soffset = 0;
        }
    }
    r = true;

out:
    if (dst != NULL)
        fclose(dst);
    free(encdata);
    free(decdata);
    return r;
}
#undef BLOCK_SIZE

#define BLOCK_SIZE  0x8000
static bool ExtractFile(FILE* in, uint64_t PartDataOffset, uint64_t FileOffset, uint64_t Size, char* FileName, uint16_t ContentID)
{
    bool r = false;
    char* encdata = malloc(BLOCK_SIZE);
    char* decdata = malloc(BLOCK_SIZE);
    assert(encdata != NULL);
    assert(decdata != NULL);
    uint64_t Wrote = 0;

    //printf("PO:%08llX FO:%08llX FS:%llu\n", PartDataOffset, FileOffset, Size );

    // Calc real offset
    uint64_t roffset = FileOffset / BLOCK_SIZE * BLOCK_SIZE;
    uint64_t soffset = FileOffset - (FileOffset / BLOCK_SIZE * BLOCK_SIZE);
    //printf("Extracting:\"%s\" RealOffset:%08llX RealOffset:%08llX\n", FileName, roffset, soffset );

    FILE* dst = fopen_utf8(FileName, "wb");
    if (dst == NULL) {
        fprintf(stderr, "ERROR: Could not create \"%s\"\n", FileName);
        goto out;
    }
    uint8_t IV[16];
    memset(IV, 0, sizeof(IV));
    IV[1] = (uint8_t)ContentID;

    uint64_t WriteSize = BLOCK_SIZE;

    if (soffset + Size > WriteSize)
        WriteSize = WriteSize - soffset;

    _fseeki64(in, PartDataOffset + roffset, SEEK_SET);

    while (Size > 0) {
        if (WriteSize > Size)
            WriteSize = Size;

        fread(encdata, sizeof(char), BLOCK_SIZE, in);

        AES_cbc_encrypt((const uint8_t*)(encdata), (uint8_t*)decdata, BLOCK_SIZE, &key, IV, AES_DECRYPT);

        Size -= fwrite(decdata + soffset, sizeof(char), WriteSize, dst);

        Wrote += WriteSize;

        if (soffset) {
            WriteSize = BLOCK_SIZE;
            soffset = 0;
        }
    }

    r = true;

out:
    if (dst != NULL)
        fclose(dst);
    free(encdata);
    free(decdata);
    return r;
}
#undef BLOCK_SIZE

int main_utf8(int argc, char** argv)
{
    int r = EXIT_FAILURE;
    uint8_t *TMD = NULL, *TIK = NULL, *CNT = NULL;
    char str[1024];

    if (argc != 3) {
        printf("%s %s (c) 2013-2015 crediar, (c) 2020 VitaSmith\n\n"
            "Usage: %s <title.tmd> <title.tik>\n\n"
            "Decrypt Wii U NUS content files.\n\n",
            appname(argv[0]), APP_VERSION_STR, appname(argv[0]));
        return EXIT_SUCCESS;
    }

    uint32_t TMDLen = read_file(argv[1], &TMD);
    if (TMDLen == 0)
        goto out;

    uint32_t TIKLen = read_file(argv[2], &TIK);
    if (TIKLen == 0)
        goto out;

    TitleMetaData* tmd = (TitleMetaData*)TMD;

    if (tmd->Version != 1) {
        fprintf(stderr, "ERROR: Unsupported TMD Version: %u\n", tmd->Version);
        goto out;
    }

    printf("Title version:%u\n", getbe16(&tmd->TitleVersion));
    printf("Content Count:%u\n", getbe16(&tmd->ContentCount));

    if (strcmp((char*)TMD + 0x140, "Root-CA00000003-CP0000000b") == 0) {
        AES_set_decrypt_key((const uint8_t*)WiiUCommonKey, sizeof(WiiUCommonKey) * 8, &key);
    }
    else if (strcmp((char*)TMD + 0x140, "Root-CA00000004-CP00000010") == 0) {
        AES_set_decrypt_key((const uint8_t*)WiiUCommonDevKey, sizeof(WiiUCommonDevKey) * 8, &key);
    } else {
        fprintf(stderr, "ERROR: Unknown Root type: \"%s\"\n", TMD + 0x140);
        goto out;
    }

    memset(title_id, 0, sizeof(title_id));

    memcpy(title_id, TMD + 0x18C, 8);
    memcpy(enc_title_key, TIK + 0x1BF, 16);

    AES_cbc_encrypt(enc_title_key, dec_title_key, sizeof(dec_title_key), &key, title_id, AES_DECRYPT);
    AES_set_decrypt_key(dec_title_key, sizeof(dec_title_key) * 8, &key);

    char iv[16];
    memset(iv, 0, sizeof(iv));

    sprintf(str, "%08X.app", getbe32(&tmd->Contents[0].ID));

    uint32_t CNTLen = read_file(str, &CNT);
    if (CNTLen == 0) {
        sprintf(str, "%08X", getbe32(&tmd->Contents[0].ID));
        CNTLen = read_file(str, &CNT);
        if (CNTLen == 0) {
            fprintf(stderr, "ERROR: Failed to open content: %02X\n", getbe32(&tmd->Contents[0].ID));
            goto out;
        }
    }

    if (getbe64(&tmd->Contents[0].Size) != (uint64_t)CNTLen) {
        fprintf(stderr, "ERROR: Size of content %u is wrong: %u:%I64u\n",
            getbe32(&tmd->Contents[0].ID), CNTLen, getbe64(&tmd->Contents[0].Size));
        goto out;
    }

    AES_cbc_encrypt((const uint8_t*)(CNT), (uint8_t*)(CNT), CNTLen, &key, (uint8_t*)(iv), AES_DECRYPT);

    if (getbe32(CNT) != FST_MAGIC) {
        sprintf(str, "%08X.dec", getbe32(&tmd->Contents[0].ID));
        fprintf(stderr, "ERROR: Unexpected content magic. Dumping decrypted file as \"%s\"\n", str);
        FileDump(str, CNT, CNTLen);
        goto out;
    }

    struct FST* _fst = (struct FST*)(CNT);

    printf("FSTInfo Entries: %u\n", getbe32(&_fst->EntryCount));
    if (getbe32(&_fst->EntryCount) > MAX_ENTRIES) {
        fprintf(stderr, "ERROR: Too many entries\n");
        goto out;
    }

    struct FEntry* fe = (struct FEntry*)(CNT + 0x20 + (uintptr_t)getbe32(&_fst->EntryCount) * 0x20);

    uint32_t Entries = getbe32(CNT + 0x20 + (uintptr_t)getbe32(&_fst->EntryCount) * 0x20 + 8);
    uint32_t NameOff = 0x20 + getbe32(&_fst->EntryCount) * 0x20 + Entries * 0x10;

    printf("FST entries: %u\n", Entries);

    char Path[1024] = { 0 };
    uint32_t Entry[16];
    uint32_t LEntry[16];

    uint32_t level = 0;

    for (uint32_t i = 1; i < Entries; i++) {
        if (level > 0) {
            while ((level >= 1) && (LEntry[level - 1] == i))
                level--;
        }

        if (fe[i].Type & 1) {
            Entry[level] = i;
            LEntry[level++] = getbe32(&fe[i].NextOffset);
            if (level >= MAX_LEVELS) {
                fprintf(stderr, "ERROR: Too many levels\n");
                break;
            }
        } else {
            uint32_t Offset;
            memset(Path, 0, sizeof(Path));

            for (uint32_t j = 0; j < level; j++) {
                if (j)
                    Path[strlen(Path)] = '\\';
                Offset = getbe32(&fe[Entry[j]].TypeName) & 0x00FFFFFF;
                memcpy(Path + strlen(Path), CNT + NameOff + Offset, strlen((char*)CNT + NameOff + Offset));
                create_path(Path);
            }
            if (level > 0)
                Path[strlen(Path)] = '\\';
            Offset = getbe32(&fe[i].TypeName) & 0x00FFFFFF;
            memcpy(Path + strlen(Path), CNT + NameOff + Offset, strlen((char*)CNT + NameOff + Offset));

            uint32_t CNTSize = getbe32(&fe[i].FileLength);
            uint64_t CNTOff = ((uint64_t)getbe32(&fe[i].FileOffset));

            if ((getbe16(&fe[i].Flags) & 4) == 0)
                CNTOff <<= 5;

            printf("Size:%07X Offset:0x%010llX CID:%02X U:%02X %s\n", CNTSize, CNTOff,
                getbe16(&fe[i].ContentID), getbe16(&fe[i].Flags), Path);

            uint32_t ContFileID = getbe32(&tmd->Contents[getbe16(&fe[i].ContentID)].ID);

            sprintf(str, "%08X.app", ContFileID);

            if (!(fe[i].Type & 0x80)) {
                FILE* cnt = fopen_utf8(str, "rb");
                if (cnt == NULL) {
                    sprintf(str, "%08X", ContFileID);
                    cnt = fopen_utf8(str, "rb");
                    if (cnt == NULL) {
                        fprintf(stderr, "ERROR: Could not open: \"%s\"\n", str);
                        goto out;
                    }
                }
                if ((getbe16(&fe[i].Flags) & 0x440)) {
                    if (!ExtractFileHash(cnt, 0, CNTOff, getbe32(&fe[i].FileLength), Path, getbe16(&fe[i].ContentID)))
                        goto out;
                } else {
                    if (!ExtractFile(cnt, 0, CNTOff, getbe32(&fe[i].FileLength), Path, getbe16(&fe[i].ContentID)))
                        goto out;
                }
                fclose(cnt);
            }
        }
    }
    r = EXIT_SUCCESS;

out:
    free(TMD);
    free(TIK);
    free(CNT);
    return r;
}

CALL_MAIN

/*
	CDecrypt - Decrypt Wii U NUS content files [https://code.google.com/p/cdecrypt/]

	Copyright (c) 2013-2015 crediar

	CDecrypt is free software: you can redistribute it and/or modify
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
#define _CRT_SECURE_NO_WARNINGS


unsigned char WiiUCommenDevKey[16] =
{
    0x2F, 0x5C, 0x1B, 0x29, 0x44, 0xE7, 0xFD, 0x6F, 0xC3, 0x97, 0x96, 0x4B, 0x05, 0x76, 0x91, 0xFA, 
};
unsigned char WiiUCommenKey[16] =
{
    0xD7, 0xB0, 0x04, 0x02, 0x65, 0x9B, 0xA2, 0xAB, 0xD2, 0xCB, 0x0D, 0xB2, 0x7F, 0xA2, 0xB6, 0x56, 
};

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl\aes.h>
#include <openssl\sha.h>
#include <time.h>
#include <vector>
#include <direct.h>
#include <ctype.h>

#pragma comment(lib,"libeay32.lib")

typedef unsigned	__int64 u64;
typedef signed		__int64 s64;

typedef unsigned	int u32;
typedef signed		int s32;

typedef unsigned	short u16;
typedef signed		short s16;

typedef unsigned	char u8;
typedef signed		char s8;

AES_KEY key;
u8 enc_title_key[16];
u8 dec_title_key[16];
u8 title_id[16];
u8 dkey[16];

u64 H0Count = 0;
u64 H0Fail  = 0;

#pragma pack(1)

enum ContentType
{
	CONTENT_REQUIRED=	(1<< 0),	// not sure
	CONTENT_SHARED	=	(1<<15),
	CONTENT_OPTIONAL=	(1<<14),
};

typedef struct
{
	u16 IndexOffset;	//	0	 0x204
	u16 CommandCount;	//	2	 0x206
	u8	SHA2[32];			//  12 0x208
} ContentInfo;

typedef struct
{
	u32 ID;					//	0	 0xB04
	u16 Index;			//	4  0xB08
	u16 Type;				//	6	 0xB0A
	u64 Size;				//	8	 0xB0C
	u8	SHA2[32];		//  16 0xB14
} Content;

typedef struct
{
	u32 SignatureType;		// 0x000
	u8	Signature[0x100];	// 0x004

	u8	Padding0[0x3C];		// 0x104
	u8	Issuer[0x40];			// 0x140

	u8	Version;					// 0x180
	u8	CACRLVersion;			// 0x181
	u8	SignerCRLVersion;	// 0x182
	u8	Padding1;					// 0x183

	u64	SystemVersion;		// 0x184
	u64	TitleID;					// 0x18C 
	u32	TitleType;				// 0x194 
	u16	GroupID;					// 0x198 
	u8	Reserved[62];			// 0x19A 
	u32	AccessRights;			// 0x1D8
	u16	TitleVersion;			// 0x1DC 
	u16	ContentCount;			// 0x1DE 
	u16 BootIndex;				// 0x1E0
	u8	Padding3[2];			// 0x1E2 
	u8	SHA2[32];					// 0x1E4
	
	ContentInfo ContentInfos[64];

	Content Contents[];		// 0x1E4 

} TitleMetaData;

struct FSTInfo
{
	u32 Unknown;
	u32 Size;
	u32 UnknownB;
	u32 UnknownC[6];
};
struct FST
{
	u32 MagicBytes;
	u32 Unknown;
	u32 EntryCount;

	u32 UnknownB[5];
	
	FSTInfo FSTInfos[];
};

struct FEntry
{
	union
	{
		struct
		{
			u32 Type				:8;
			u32 NameOffset	:24;
		};
		u32 TypeName;
	};
	union
	{
		struct		// File Entry
		{
			u32 FileOffset;
			u32 FileLength;
		};
		struct		// Dir Entry
		{
			u32 ParentOffset;
			u32 NextOffset;
		};
		u32 entry[2];
	};
	unsigned short Flags;
	unsigned short ContentID;
};

#define bs16(s) (u16)( ((s)>>8) | ((s)<<8) )
#define bs32(s) (u32)( (((s)&0xFF0000)>>8) | (((s)&0xFF00)<<8) | ((s)>>24) | ((s)<<24) )

u32 bs24( u32 i )
{
	return ((i&0xFF0000)>>16) | ((i&0xFF)<<16) | (i&0x00FF00);
}
u64 bs64( u64 i )
{
	return ((u64)(bs32(i&0xFFFFFFFF))<<32) | (bs32(i>>32));
}
char *ReadFile( const char *Name, u32 *Length )
{
	FILE *in = fopen(Name,"rb");
	if( in == NULL )
	{
		//perror("");
		return NULL;
	}

	fseek( in, 0, SEEK_END );
	*Length = ftell(in);
	
	fseek( in, 0, 0 );

	char *Data = new char[*Length];

	u32 read = fread( Data, 1, *Length, in );

	fclose( in );

	return Data;
}
void FileDump( const char *Name, void *Data, u32 Length )
{
	if( Data == NULL )
	{
		printf("zero ptr");
		return;
	}
	if( Length == 0 )
	{
		printf("zero sz");
		return;
	}
	FILE *Out = fopen( Name, "wb" );
	if( Out == NULL )
	{
		perror("");
		return;
	}

	if( fwrite( Data, 1, Length, Out ) != Length )
  {
		perror("");
  }

	fclose( Out );
}
static char ascii(char s)
{
  if(s < 0x20) return '.';
  if(s > 0x7E) return '.';
  return s;
}
void hexdump(void *d, s32 len)
{
  u8 *data;
  s32 i, off;
  data = (u8*)d;
  for (off=0; off<len; off += 16)
  {
    printf("%08x  ",off);
    for(i=0; i<16; i++)
      if((i+off)>=len)
		  printf("   ");
      else
		  printf("%02x ",data[off+i]);

    printf(" ");
    for(i=0; i<16; i++)
      if((i+off)>=len) printf(" ");
      else printf("%c",ascii(data[off+i]));
    printf("\n");
  }
}
#define	BLOCK_SIZE	0x10000
void ExtractFileHash( FILE *in, u64 PartDataOffset, u64 FileOffset, u64 Size, char *FileName, u16 ContentID )
{
	char encdata[BLOCK_SIZE];
	char decdata[BLOCK_SIZE];
	u8 IV[16];
	u8 hash[SHA_DIGEST_LENGTH];
	u8 H0[SHA_DIGEST_LENGTH];
	u8 Hashes[0x400];

	u64 Wrote			= 0;
	u64 WriteSize = 0xFC00;	// Hash block size
	u64 Block			= (FileOffset / 0xFC00) & 0xF;
		
	FILE *out = fopen( FileName, "wb" );
	if( out == NULL )
	{
		printf("Could not create \"%s\"\n", FileName );
		perror("");
		exit(0);
	}

	u64 roffset = FileOffset / 0xFC00 * BLOCK_SIZE;
	u64 soffset = FileOffset - (FileOffset / 0xFC00 * 0xFC00);

	if( soffset+Size > WriteSize )
		WriteSize = WriteSize - soffset;

	_fseeki64( in, PartDataOffset+roffset, SEEK_SET );
	while(Size > 0)
	{
		if( WriteSize > Size )
			WriteSize = Size;

		fread( encdata, sizeof( char ), BLOCK_SIZE, in);
		
		memset( IV, 0, sizeof(IV) );
		IV[1] = (u8)ContentID;
		AES_cbc_encrypt( (const u8 *)(encdata), (u8 *)Hashes, 0x400, &key, IV, AES_DECRYPT );		
		
		memcpy( H0, Hashes+0x14*Block, SHA_DIGEST_LENGTH );

		memcpy( IV, Hashes+0x14*Block, sizeof(IV) );
		if( Block == 0 )
			IV[1] ^= ContentID;
		AES_cbc_encrypt( (const u8 *)(encdata+0x400), (u8 *)decdata, 0xFC00, &key, IV, AES_DECRYPT );

		SHA1( (const u8 *)decdata, 0xFC00, hash );
		if( Block == 0 )
			hash[1] ^= ContentID;
		H0Count++;
		if( memcmp( hash, H0, SHA_DIGEST_LENGTH ) != 0 )
		{
			H0Fail++;
			hexdump( hash, SHA_DIGEST_LENGTH );
			hexdump( Hashes, 0x100 );
			hexdump( decdata, 0x100 );
			printf("Failed to verify H0 hash\n");
			exit(0);
		}

		Size -= fwrite( decdata+soffset, sizeof( char ), WriteSize, out);

		Wrote+=WriteSize;

		Block++;
		if( Block >= 16 )
				Block = 0;

		if( soffset )
		{
			WriteSize = 0xFC00;
			soffset = 0;
		}
	}
	
	fclose( out );
}
#undef BLOCK_SIZE
#define	BLOCK_SIZE	0x8000
void ExtractFile( FILE *in, u64 PartDataOffset, u64 FileOffset, u64 Size, char *FileName, u16 ContentID )
{
	char encdata[BLOCK_SIZE];
	char decdata[BLOCK_SIZE];
	u64 Wrote=0;
	u64 Block			= (FileOffset / BLOCK_SIZE) & 0xF;

	//printf("PO:%08llX FO:%08llX FS:%llu\n", PartDataOffset, FileOffset, Size );

	//calc real offset
	u64 roffset = FileOffset / BLOCK_SIZE * BLOCK_SIZE;
	u64 soffset = FileOffset - (FileOffset / BLOCK_SIZE * BLOCK_SIZE);
	//printf("Extracting:\"%s\" RealOffset:%08llX RealOffset:%08llX\n", FileName, roffset, soffset );
	
	FILE *out = fopen( FileName, "wb" );
	if( out == NULL )
	{
		printf("Could not create \"%s\"\n", FileName );
		perror("");
		exit(0);
	}
	u8 IV[16];
	memset( IV, 0, sizeof(IV) );
	IV[1] = (u8)ContentID;

	u64 WriteSize = BLOCK_SIZE;

	if( soffset+Size > WriteSize )
		WriteSize = WriteSize - soffset;

	_fseeki64( in, PartDataOffset+roffset, SEEK_SET );
	
	while(Size > 0)
	{
		if( WriteSize > Size )
				WriteSize = Size;

		fread( encdata, sizeof( char ), BLOCK_SIZE, in);
		
		AES_cbc_encrypt( (const u8 *)(encdata), (u8 *)decdata, BLOCK_SIZE, &key, IV, AES_DECRYPT);

		Size -= fwrite( decdata+soffset, sizeof( char ), WriteSize, out);

		Wrote+=WriteSize;

		if( soffset )
		{
			WriteSize = BLOCK_SIZE;
			soffset = 0;
		}
	}
	
	fclose( out );
}
s32 main( s32 argc, char*argv[])
{
	char str[1024];
	
	printf("CDecrypt v 2.0b by crediar\n");
	printf("Built: %s %s\n", __TIME__, __DATE__ );

	if( argc != 3 )
	{
		printf("Usage:\n");
		printf(" CDecrypt.exe tmd cetk\n\n");
		return EXIT_SUCCESS;
	}

	u32 TMDLen;
	char *TMD = ReadFile( argv[1], &TMDLen );
	if( TMD == nullptr )
	{
		perror("Failed to open tmd\n");
		return EXIT_FAILURE;
	}
	
	u32 TIKLen;
	char *TIK = ReadFile( argv[2], &TIKLen );
	if( TIK == nullptr )
	{
		perror("Failed to open cetk\n");
		return EXIT_FAILURE;
	}

	TitleMetaData *tmd = (TitleMetaData*)TMD;

	if( tmd->Version != 1 )
	{
		printf("Unsupported TMD Version:%u\n", tmd->Version );
		return EXIT_FAILURE;
	}
	
	printf("Title version:%u\n", bs16(tmd->TitleVersion) );
	printf("Content Count:%u\n", bs16(tmd->ContentCount) );

	if( strcmp( TMD+0x140, "Root-CA00000003-CP0000000b" ) == 0 )
	{
		AES_set_decrypt_key( (const u8*)WiiUCommenKey, sizeof(WiiUCommenKey)*8, &key );
	}
	else if( strcmp( TMD+0x140, "Root-CA00000004-CP00000010" ) == 0 )
	{
		AES_set_decrypt_key( (const u8*)WiiUCommenDevKey, sizeof(WiiUCommenDevKey)*8, &key );
	}
	else
	{
		printf("Unknown Root type:\"%s\"\n", TMD+0x140 );
		return EXIT_FAILURE;
	}	

	memset( title_id, 0, sizeof(title_id) );
	
	memcpy( title_id, TMD + 0x18C, 8 );
	memcpy( enc_title_key, TIK + 0x1BF, 16 );
	
	AES_cbc_encrypt(enc_title_key, dec_title_key, sizeof(dec_title_key), &key, title_id, AES_DECRYPT);
	AES_set_decrypt_key( dec_title_key, sizeof(dec_title_key)*8, &key);
		
	char iv[16];
	memset( iv, 0, sizeof(iv) );
	
	sprintf( str, "%08X.app", bs32(tmd->Contents[0].ID) );
	
	u32 CNTLen;
	char *CNT = ReadFile( str, &CNTLen );
	if( CNT == (char*)NULL )
	{
		sprintf( str, "%08X", bs32(tmd->Contents[0].ID) );
		CNT = ReadFile( str, &CNTLen );
		if( CNT == (char*)NULL )
		{
			printf("Failed to open content:%02X\n", bs32(tmd->Contents[0].ID) );
			return EXIT_FAILURE;
		}
	}

	if( bs64(tmd->Contents[0].Size) != (u64)CNTLen )
	{
		printf("Size of content:%u is wrong: %u:%I64u\n", bs32(tmd->Contents[0].ID), CNTLen, bs64(tmd->Contents[0].Size) );
		return EXIT_FAILURE;
	}

	AES_cbc_encrypt( (const u8 *)(CNT), (u8 *)(CNT), CNTLen, &key, (u8*)(iv), AES_DECRYPT );	

	if( bs32(*(u32*)CNT) != 0x46535400 )
	{
		sprintf( str, "%08X.dec", bs32(tmd->Contents[0].ID) );
		FileDump( str, CNT, CNTLen );
		return EXIT_FAILURE;
	}
	
	FST *_fst = (FST*)(CNT);

	printf("FSTInfo Entries:%u\n", bs32(_fst->EntryCount) );
	if( bs32(_fst->EntryCount) > 90000 )
	{
		return EXIT_FAILURE;
	}
	
	FEntry *fe = (FEntry*)(CNT+0x20+bs32(_fst->EntryCount)*0x20);
	
	u32 Entries = bs32(*(u32*)(CNT+0x20+bs32(_fst->EntryCount)*0x20+8));
	u32 NameOff = 0x20 + bs32(_fst->EntryCount) * 0x20 + Entries * 0x10;
	u32 DirEntries = 0;
	
	printf("FST entries:%u\n", Entries );

	char *Path = new char[1024];
	s32 Entry[16];
	s32 LEntry[16];
	
	s32 level=0;

	for( u32 i=1; i < Entries; ++i )
	{
		if( level )
		{
			while( LEntry[level-1] == i )
			{
				//printf("[%03X]leaving :\"%s\" Level:%d\n", i, CNT + NameOff + bs24( fe[Entry[level-1]].NameOffset ), level );
				level--;
			}
		}

		if( fe[i].Type & 1 )
		{
			Entry[level] = i;
			LEntry[level++] = bs32( fe[i].NextOffset );
			if( level > 15 )	// something is wrong!
			{
				printf("level error:%u\n", level );
				break;
			}
		}
		else
		{
			memset( Path, 0, 1024 );

			for( s32 j=0; j<level; ++j )
			{
				if(j)
					Path[strlen(Path)] = '\\';
				memcpy( Path+strlen(Path), CNT + NameOff + bs24( fe[Entry[j]].NameOffset), strlen(CNT + NameOff + bs24( fe[Entry[j]].NameOffset) ) );
				_mkdir(Path);
			}
			if(level)
				Path[strlen(Path)] = '\\';
			memcpy( Path+strlen(Path), CNT + NameOff + bs24( fe[i].NameOffset ), strlen(CNT + NameOff + bs24( fe[i].NameOffset )) );

			u32 CNTSize = bs32(fe[i].FileLength);
			u64 CNTOff  = ((u64)bs32(fe[i].FileOffset));

			if( (bs16(fe[i].Flags) & 4) == 0 )
			{
				CNTOff <<= 5;
			}
			
			printf("Size:%07X Offset:0x%010llX CID:%02X U:%02X %s\n", CNTSize, CNTOff, bs16(fe[i].ContentID), bs16(fe[i].Flags), Path );

			u32 ContFileID = bs32(tmd->Contents[bs16(fe[i].ContentID)].ID);
			
			sprintf( str, "%08X.app", ContFileID );

			if(!(fe[i].Type & 0x80))
			{
				FILE *cnt = fopen( str, "rb" );
				if( cnt == NULL )
				{
					sprintf( str, "%08X", ContFileID );
					cnt = fopen( str, "rb" );
					if( cnt == NULL )
					{
						printf("Could not open:\"%s\"\n", str );			
						perror("");
						return EXIT_FAILURE;
					}
				}
				if( (bs16(fe[i].Flags) & 0x440) )
				{
					ExtractFileHash( cnt, 0, CNTOff, bs32(fe[i].FileLength), Path, bs16(fe[i].ContentID) );
				}
				else
				{
					ExtractFile( cnt, 0, CNTOff, bs32(fe[i].FileLength), Path, bs16(fe[i].ContentID) );
				}
				fclose(cnt);
			}
		}
	}
	return EXIT_SUCCESS;
}
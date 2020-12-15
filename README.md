# CDecrypt

[![Build status](https://img.shields.io/appveyor/ci/VitaSmith/cdecrypt.svg?style=flat-square)](https://ci.appveyor.com/project/VitaSmith/cdecrypt)
[![Github stats](https://img.shields.io/github/downloads/VitaSmith/cdecrypt/total.svg?style=flat-square)](https://github.com/VitaSmith/cdecrypt/releases)
[![Latest release](https://img.shields.io/github/release-pre/VitaSmith/cdecrypt?style=flat-square)](https://github.com/VitaSmith/cdecrypt/releases)

### Description

A utility that decrypts Wii U NUS content files.

### Details

This is a fork of https://code.google.com/p/cdecrypt intended for modders who
want to explore or modify the content of the Wii U applications they own.

Unlike other clones, this version of cdecrypt has **no** external dependencies
such as OpenSSL libraries and whatnot: A single executable file is all you need.
It also supports international characters, does not need to reside in the same
directory as the NUS content, and can be compiled for Linux or macOS.

### Usage

```
cdecrypt <NUS file or directory> [<target directory or existing file>]
```

If only one parameter is specified, the content is extracted into the same
directory where the NUS files reside. If an existing file is provided as the
second parameter, it is ignored (to preserve compatibility with the previous
versions of CDecrypt). If the second parameter is not an existing file, then
it is used as the target directory to extract files in, with any intermediate
directories created if needed.

Note that on Windows, you can drag and drop a directory/file directly onto
`cdecrypt.exe`.

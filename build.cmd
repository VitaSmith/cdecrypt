@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\Tools\VsDevCmd.bat" -arch=amd64 -host_arch=amd64 -no_logo
cd /d "%~dp0"

set OPENSSL_PATH=C:\Program Files\OpenSSL-Win64

set CL=/nologo /errorReport:none /Ox /Gm- /GF /GS- /MP /MT /W4 /WX /wd4200 /wd4201 /wd4204 /wd4214 /wd4324 /wd4996 /D_UNICODE /D_CRT_SECURE_NO_DEPRECATE /UNDEBUG /I"%OPENSSL_PATH%\include" /link /LIBPATH:"%OPENSSL_PATH%\lib"
set LINK=/errorReport:none /INCREMENTAL:NO

if not "%1"=="" goto %1

:cdecrypt
echo.
set APP_NAME=cdecrypt
cl.exe %APP_NAME%.c util.c sha1.c /Fe%APP_NAME%.exe
if %ERRORLEVEL% neq 0 goto out
echo =^> %APP_NAME%.exe
if not "%1"=="" goto out

:out
endlocal
if %ERRORLEVEL% neq 0 pause

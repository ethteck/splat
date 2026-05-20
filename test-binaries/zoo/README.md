# Win32 PE test corpus

Freely-redistributable Windows PE binaries useful for exercising the
splat win32 platform. None of these are committed to the repo (they're
re-downloadable and live behind their respective licenses); the
`.gitignore` here keeps the directory empty in git.

Each entry: project + version + arch / era / license / direct URL.

## 1995-1999 — Win95/98, MSVC 4-6 era (PE32 only)

| Binary | License | URL |
| --- | --- | --- |
| Info-ZIP UnZip 6.00 (PE32) | Info-ZIP (BSD-style) | <ftp://ftp.info-zip.org/pub/infozip/win32/unz600xn.exe> |
| DOSBox 0.74-3 installer (PE32, NSIS wrapper) | GPL-2.0 | <https://sourceforge.net/projects/dosbox/files/dosbox/0.74-3/DOSBox0.74-3-win32-installer.exe/download> |
| OpenTTD 1.0.0 win9x (PE32) | GPL-2.0 | <https://cdn.openttd.org/openttd-releases/1.0.0/openttd-1.0.0-windows-win9x.zip> |

## 2000-2003 — Win2K/XP, MSVC 6/7

| Binary | License | URL |
| --- | --- | --- |
| Python 2.7.18 x86 (PE32) | PSF | <https://www.python.org/ftp/python/2.7.18/python-2.7.18.msi> |
| Python 2.7.18 amd64 (PE32+) | PSF | <https://www.python.org/ftp/python/2.7.18/python-2.7.18.amd64.msi> |
| PuTTY 0.60 x86 (PE32) | MIT | <https://the.earth.li/~sgtatham/putty/0.60/x86/putty.exe> |

## 2004-2009 — XP/Vista, MSVC 8/9, early x64

| Binary | License | URL |
| --- | --- | --- |
| 7-Zip 9.20 x86 (PE32) | LGPL-2.1 | <https://www.7-zip.org/a/7z920.exe> |
| Notepad2 4.2.25 x86 (PE32) | freeware (BSD source) | <https://www.flos-freeware.ch/zip/notepad2_4.2.25_x86.zip> |
| VLC 1.1.11 win32 (PE32, plus DLLs) | GPL-2.0 | <https://download.videolan.org/pub/videolan/vlc/1.1.11/win32/vlc-1.1.11-win32.zip> |
| PuTTY 0.62 x86 (PE32) | MIT | <https://the.earth.li/~sgtatham/putty/0.62/x86/putty.exe> |
| ScummVM 1.9.0 win32 (PE32) | GPL-2.0 | <https://downloads.scummvm.org/frs/scummvm/1.9.0/scummvm-1.9.0-win32.zip> |
| Pidgin 2.10.12 win32-bin (PE32 + DLLs, plain zip) | GPL-2.0 | <https://sourceforge.net/projects/pidgin/files/Pidgin/2.10.12/pidgin-2.10.12-win32-bin.zip/download> |

## 2010-2014 — Win7, MSVC 10/11, PE32+ mainstream

| Binary | License | URL |
| --- | --- | --- |
| 7-Zip 16.04 x64 (PE32+) | LGPL-2.1 | <https://www.7-zip.org/a/7z1604-x64.exe> |
| 7-Zip 16.04 x86 (PE32) | LGPL-2.1 | <https://www.7-zip.org/a/7z1604.exe> |
| OpenTTD 1.5.3 win64 (PE32+) | GPL-2.0 | <https://cdn.openttd.org/openttd-releases/1.5.3/openttd-1.5.3-windows-win64.zip> |
| OpenTTD 1.5.3 win32 (PE32) | GPL-2.0 | <https://cdn.openttd.org/openttd-releases/1.5.3/openttd-1.5.3-windows-win32.zip> |
| VLC 2.0.0 win32 (PE32) | GPL-2.0 | <https://download.videolan.org/pub/videolan/vlc/2.0.0/win32/vlc-2.0.0-win32.zip> |
| Python 3.4.4 amd64 (PE32+) | PSF | <https://www.python.org/ftp/python/3.4.4/python-3.4.4.amd64.msi> |
| PuTTY 0.70 x86 (PE32) | MIT | <https://the.earth.li/~sgtatham/putty/0.70/w32/putty.exe> |

## 2015-2025 — Win10/11, MSVC 14.x (CFG, SafeSEH, HighEntropyVA)

| Binary | License | URL |
| --- | --- | --- |
| 7-Zip 19.00 x64 (PE32+) | LGPL-2.1 | <https://www.7-zip.org/a/7z1900-x64.exe> |
| 7-Zip 23.01 x86 (PE32) | LGPL-2.1 | <https://www.7-zip.org/a/7z2301.exe> |
| Notepad++ 7.9.5 portable x64 (PE32+) | GPL-3.0 | <https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v7.9.5/npp.7.9.5.portable.x64.zip> |
| Notepad++ 8.6.9 portable x86 (PE32) | GPL-3.0 | <https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.6.9/npp.8.6.9.portable.zip> |
| VLC 3.0.20 win64 (PE32+) | GPL-2.0 | <https://download.videolan.org/pub/videolan/vlc/3.0.20/win64/vlc-3.0.20-win64.zip> |
| ScummVM 2.7.0 win32-x86_64 (PE32+) | GPL-2.0 | <https://downloads.scummvm.org/frs/scummvm/2.7.0/scummvm-2.7.0-win32-x86_64.zip> |
| WinLibs GCC 16.1.0 MinGW-w64 x64 (gcc.exe + bundled tools) | GPL-3.0 + Runtime Lib Exception | <https://github.com/brechtsanders/winlibs_mingw/releases/download/16.1.0posix-14.0.0-msvcrt-r2/winlibs-x86_64-posix-seh-gcc-16.1.0-mingw-w64msvcrt-14.0.0-r2.zip> |
| WinLibs GCC 16.1.0 MinGW-w64 x86 (PE32) | GPL-3.0 + Runtime Lib Exception | <https://github.com/brechtsanders/winlibs_mingw/releases/download/16.1.0posix-14.0.0-msvcrt-r2/winlibs-i686-posix-dwarf-gcc-16.1.0-mingw-w64msvcrt-14.0.0-r2.zip> |

## ARM64 PE — Win10/11 ARM (MSVC 14.x ARM64 codegen)

| Binary | License | URL |
| --- | --- | --- |
| curl-for-win 8.20.0_2 ARM64 | curl license (MIT-like) | <https://curl.se/windows/dl-8.20.0_2/curl-8.20.0_2-win64a-mingw.zip> |
| Git for Windows 2.54.0 PortableGit ARM64 | GPL-2.0 | <https://github.com/git-for-windows/git/releases/download/v2.54.0.windows.1/PortableGit-2.54.0-arm64.7z.exe> |
| 7-Zip 26.01 ARM64 | LGPL-2.1 | <https://github.com/ip7z/7zip/releases/download/26.01/7z2601-arm64.exe> |
| FireDaemon OpenSSL 3.6.2 (x86 + x64 + ARM64 libcrypto/libssl) | Apache-2.0 | <https://download.firedaemon.com/FireDaemon-OpenSSL/openssl-3.6.2.zip> |

## Sysinternals / Microsoft modern (covered in baseline tests)

| Binary | Notes |
| --- | --- |
| PuTTY x64 latest | <https://the.earth.li/~sgtatham/putty/latest/w64/putty.exe> — MSVC 14.x, 10 sections, 2410 RUNTIME_FUNCTION entries |
| Sysinternals PSTools | <https://download.sysinternals.com/files/PSTools.zip> — both PE32 (`PsExec.exe`, SafeSEH) and PE32+ (`PsExec64.exe`, 1049 .pdata) |
| AccessChk (Sysinternals) | bundled in PSTools.zip |
| ReactOS prebuilt | <https://reactos.org/getbuilds/> — open-source Windows reimplementation, modern PE features |

## ARM32 PE

Not commonly distributed for non-CE Windows; splat init() rejects
ARM32 with an arch-specific error. ARM64 is the working ARM tier.

## Verified results

Repo's committed corpus (under `test-binaries/`):

- `test-binaries/Server/server.dll` — MSVC 6.0 PE32 DLL with `.reloc` — 286720/286720 byte-identical round-trip via `exact_encoding`
- `test-binaries/Europa1400Gold_TL.exe` — MSVC 6.0 PE32 EXE, RELOCS_STRIPPED — `.text` 2490368/2490368 byte-identical via `exact_encoding`

Adding any of the binaries above and running `create_config.py
<binary>` produces an assembleable splat output.

## Extraction notes

The MSI / NSIS / 7z-SFX wrappers (Python, DOSBox, Pidgin, Git for
Windows, 7-Zip self-installers) need extraction first:

```
7z x dosbox-installer.exe          # NSIS, 7z, MSI all supported
msiextract python-2.7.18.msi       # alternative for MSIs
```

The plain `.zip` candidates (Notepad++ portable, VLC, OpenTTD, ScummVM,
Pidgin win32-bin, WinLibs, curl-for-win, FireDaemon) extract straight
to a tree of PEs — preferred for hermetic test setups.

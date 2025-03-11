# SleepShell

## Description
SleepShell, crafted by SleepTheGod, is a potent 64-bit Windows shellcode injector. Targeting explorer.exe, it spawns cmd.exe via CreateProcessA. With dynamic API resolution and robust error handling, this admin-privileged tool showcases sophisticated process injection techniques in a compact package.

## Features
- 64-bit Windows compatible shellcode
- Injects into explorer.exe process
- Spawns cmd.exe using CreateProcessA
- Dynamic resolution of API addresses
- Comprehensive error handling
- Clean memory management

## Requirements
- Windows 64-bit operating system
- Administrative privileges
- Microsoft Visual C++ compiler (MSVC)
- ntdll.lib and kernel32.lib for linking

## Compilation
Compile using MSVC with

cl.exe /Fe:SleepShell.exe SleepShell.c /link ntdll.lib kernel32.lib


## Usage
1. Compile the source code using the command above
2. Run SleepShell.exe with administrative privileges
3. Program will print "Made By SleepTheGod" and inject shellcode
4. A new cmd.exe window will spawn if successful

## Code Details
- File: SleepShell.c
- Size: 6.07 KB
- Lines: 157
- Location: https://github.com/SleepTheGod/SleepShell/blob/main/SleepShell.c

## Warning
- Requires admin rights to function
- May be detected by antivirus software
- Use responsibly and only in authorized testing environments

## Author
- Created by: SleepTheGod
- GitHub: https://github.com/SleepTheGod

## License
© 2025 SleepTheGod. All rights reserved.

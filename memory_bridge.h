#pragma once

typedef void* HANDLE;
typedef unsigned long long uintptr_t;
typedef unsigned long long size_t;

typedef char MB_BOOL;

typedef struct
{
    HANDLE handle;
    int pid;
    uintptr_t baseModule;
} attached_process;

attached_process* mem_attach(int pid);
attached_process* mem_attachx(const char* name);

MB_BOOL mem_read(attached_process* proc, uintptr_t address, void* buffer, size_t len);
MB_BOOL mem_write(attached_process* proc,uintptr_t address,const char* buffer,int len);

uintptr_t mem_read_ptr(attached_process* proc, uintptr_t address);
const char* mem_read_cstr(attached_process* proc, uintptr_t address);
const char* mem_read_cppstr(attached_process* proc, uintptr_t address);

uintptr_t mem_get_module_base(attached_process* proc);

#pragma once

extern "C"
{
    #include "memory_bridge.h"
}

#include "pattern.hpp"

const uintptr_t offset_fakedatamodel = 0x1B8;
const uintptr_t offset_children = 0x70; //0x68 // 0x80
const uintptr_t offset_name = 0xB0; // 0x80 // 0x78

const uintptr_t offset_RakPeerCrypto = 0x3270; //0x2F30

/*
typedef struct 
{
    uintptr_t addy;
} rbx_instance;
*/

typedef uintptr_t rbx_instance; // nyheheh
typedef uintptr_t rbx_rakpeercrypto; // nyheheh

typedef struct
{
    uintptr_t start;
    uintptr_t end;
    uintptr_t allocated;
} vector_t;


static const char* rbx_get_name(attached_process* roblox, rbx_instance* instance)
{
    uintptr_t name_ptr = mem_read_ptr(roblox, (uintptr_t)instance + offset_name);

    return mem_read_cppstr(roblox, name_ptr);
}

static rbx_instance* rbx_findfirstchild(attached_process* roblox, rbx_instance* instance, const char* name)
{
    vector_t vec;
    mem_read(roblox, mem_read_ptr(roblox, (uintptr_t)instance + offset_children), & vec, sizeof(vector_t));

    uintptr_t iter = vec.start;

    while (iter != vec.end)
    {
        const char* child_name = rbx_get_name(roblox, (rbx_instance*)mem_read_ptr(roblox, iter));

        if (strcmp(child_name, name) == 0)
        {
            g_free((void*)child_name);
            return (rbx_instance*)mem_read_ptr(roblox, iter);
        }

        g_free((void*)child_name);

        iter += 16;
    }

    return 0;
}

static rbx_instance* rbx_getdatamodel(attached_process* roblox)
{
    std::vector<uintptr_t> res = PatternScanAll(roblox->handle, "47 75 69 52 6F 6F 74 00 47 75 69 49 74 65 6D");

    for (uintptr_t dm2 : res)
    {
        auto dm = (rbx_instance*)(mem_read_ptr(roblox, dm2 + 0x38) + offset_fakedatamodel);

        if (rbx_findfirstchild(roblox, dm, "NetworkClient"))
        {
            return dm;
        }
    }

    return 0;
}


static rbx_rakpeercrypto* rbx_getrakpeercrypto(attached_process* roblox, rbx_instance* replicator)
{
    return (rbx_rakpeercrypto*)mem_read_ptr(roblox, (uintptr_t)replicator + offset_RakPeerCrypto);
}

static void rbx_getdecryptionkeys(attached_process* roblox, rbx_rakpeercrypto* crypto, unsigned char tx[0x20], unsigned char rx[0x20])
{
    mem_read(roblox, (uintptr_t)crypto + 0x40, tx, 0x20);
    mem_read(roblox, (uintptr_t)crypto + 0x60, rx, 0x20);
}

static char rbx_getcryptoformat(attached_process* roblox, rbx_rakpeercrypto* crypto)
{
    char ret = 0;
    mem_read(roblox, (uintptr_t)crypto + 0x2D, &ret, 0x1);

    return ret;
}

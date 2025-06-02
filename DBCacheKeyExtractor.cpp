// Disable security warnings for using older C functions
#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>

#include <stdint.h>
#include <stdio.h>

#include "Zydis.h"

static bool maskedCompare(const uint8_t *a, const uint8_t *b, const uint8_t *mask, int len)
{
    for (int i = 0; i < len; i++)
        if ((a[i] & mask[i]) != (b[i] & mask[i]))
            return false;
    return true;
}

int main(int argc, char **argv)
{
    // Check if a file path was provided as command line argument
    bool debug = getenv("DBCKE_DEBUG") != nullptr;
    if (argc < 2)
    {
        printf("Usage: %s <dumped_wow.exe>", argv[0]);
        return 1;
    }

    // Open the dumped WoW executable in binary read mode
    auto exeFile = fopen(argv[1], "rb");
    fseek(exeFile, 0, FILE_END);
    auto sz = ftell(exeFile); // Get file size

    // Allocate executable memory region to load the file into
    void *region = VirtualAlloc(NULL, sz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!region)
        return 255;
    fseek(exeFile, 0, FILE_BEGIN);
    fread(region, 1, sz, exeFile); // Read entire file into memory
    fclose(exeFile);

    // Assembly pattern to search for in the executable:
    // cmp dword ptr [rax], 48544658h  ; "XFTH"
    // jnz loc_7FF6D9D94EAB
    // cmp dword ptr [rax+4], 9
    // jnz loc_7FF6D9D94EAB
    // cmp dword ptr [rax+8], 0E61Fh
    // jnz loc_7FF6D9D94EAB
    // mov [rsp+250h], rsi
    // lea rcx, [rbp+20h]
    // mov [rsp+220h], r12
    // call loc_7FF6D9D942A0  ; Target function that loads key into R8

    // Create search patterns for each register
    uint8_t patterns[ZYDIS_MAX_INSTRUCTION_LENGTH * 3][16];
    memset(patterns, 0, sizeof(patterns));
    uint8_t patternMasks[ZYDIS_MAX_INSTRUCTION_LENGTH * 3][16];
    memset(patternMasks, 0xff, sizeof(patternMasks));
    int patternSizes[16];
    memset(patternSizes, 0, sizeof(patternSizes));
    for (int reg = 0; reg < 16; reg++)
    {
        uint8_t *pattern = patterns[reg];
        uint8_t *patternMask = patternMasks[reg];
        ZydisEncoderRequest req;
        memset(&req, 0, sizeof(ZydisEncoderRequest));
        req.mnemonic = ZYDIS_MNEMONIC_CMP;
        req.machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
        req.operand_count = 2;
        req.operands[0].type = ZYDIS_OPERAND_TYPE_MEMORY;
        req.operands[0].mem.base = (ZydisRegister)(ZYDIS_REGISTER_RAX + reg);
        req.operands[0].mem.displacement = 0;
        req.operands[0].mem.size = 4;
        req.operands[1].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
        req.operands[1].imm.u = 0x48544658;

        ZyanUSize encodedSize = ZYDIS_MAX_INSTRUCTION_LENGTH;
        ZydisEncoderEncodeInstruction(&req, pattern, &encodedSize);
        patternSizes[reg] += (int)encodedSize;
        pattern += encodedSize;
        patternMask += encodedSize;

        memset(&req, 0, sizeof(ZydisEncoderRequest));
        req.mnemonic = ZYDIS_MNEMONIC_JNZ;
        req.machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
        req.operand_count = 1;
        req.operands[0].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
        req.operands[0].imm.u = 0x01020304;

        encodedSize = ZYDIS_MAX_INSTRUCTION_LENGTH;
        ZydisEncoderEncodeInstruction(&req, pattern, &encodedSize);
        patternSizes[reg] += (int)encodedSize;
        pattern += encodedSize;
        patternMask += encodedSize;
        patternMask[-1] = 0;
        patternMask[-2] = 0;
        patternMask[-3] = 0;
        patternMask[-4] = 0;

        memset(&req, 0, sizeof(ZydisEncoderRequest));
        req.mnemonic = ZYDIS_MNEMONIC_CMP;
        req.machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
        req.operand_count = 2;
        req.operands[0].type = ZYDIS_OPERAND_TYPE_MEMORY;
        req.operands[0].mem.base = (ZydisRegister)(ZYDIS_REGISTER_RAX + reg);
        req.operands[0].mem.displacement = 4;
        req.operands[0].mem.size = 4;
        req.operands[1].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
        req.operands[1].imm.u = 0x9;

        encodedSize = ZYDIS_MAX_INSTRUCTION_LENGTH;
        ZydisEncoderEncodeInstruction(&req, pattern, &encodedSize);
        patternSizes[reg] += (int)encodedSize;

        if (debug)
        {
            fprintf(stderr, "Pattern for %s:\n", ZydisRegisterGetString((ZydisRegister)(ZYDIS_REGISTER_RAX + reg)));
            for (int i = 0; i < patternSizes[reg]; i++)
                fprintf(stderr, " %02x", patterns[reg][i]);
            fprintf(stderr, "\n");
        }
    }

    // Search for the pattern in the loaded executable
    char *found = nullptr;
    for (int i = 0; i + 999 < sz; i++)
    {
        for (int reg = 0; reg < 16; reg++)
        {
            if (maskedCompare((uint8_t *)region + i, patterns[reg], patternMasks[reg], patternSizes[reg]))
            {
                // Pattern found - calculate address of target function
                found = (char *)region + i;
                break;
            }
        }
    }
    if (!found)
    {
        return 2; // Pattern not found
    }

    if (debug)
    {
        fprintf(stderr, "Pattern found at offset: %llx\n", found - (char *)region);
    }

    // Disassemble forward to the next call
    static void *startFn = nullptr;
    ZydisDisassembledInstruction inst;
    while (ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, (ZyanU64)found, (void *)found, 999, &inst)))
    {
        if (debug)
        {
            fprintf(stderr, "0x%016p   %s\n", found, inst.text);
        }

        if (inst.info.mnemonic == ZYDIS_MNEMONIC_CALL)
        {
            ZydisCalcAbsoluteAddress(&inst.info, &inst.operands[0], (ZyanU64)found, (ZyanU64 *)&startFn);
            if (debug)
            {
                fprintf(stderr, "Start function found at offset: %llx\n", (char *)startFn - (char *)region);
            }
            break;
        }

        found += inst.info.length;
    }

    // Buffer to store the extracted cache key and synchronization objects
    static uint8_t key[16];
    static HANDLE keyReadyEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

    // Set up vectored exception handler to capture the key
    // The target function will:
    // 1. Load the key into a buffer on its stack
    // 2. Move the buffer address into R8
    // 3. Try to initialize HMAC state at rcx (which is null)
    // This causes an access violation, letting us capture the key from R8
    AddVectoredExceptionHandler(
        1, (PVECTORED_EXCEPTION_HANDLER)([](_EXCEPTION_POINTERS *ExceptionInfo) -> long {
            if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION)
            {
                // At this point, R8 contains pointer to the key buffer
                memcpy(key, (void *)ExceptionInfo->ContextRecord->R8, 16);
                SetEvent(keyReadyEvent);           // Signal that key is ready
                SuspendThread(GetCurrentThread()); // Suspend thread to prevent exception propagation
            }
            else
            {
                printf("Unhandled exception: %08x\n", ExceptionInfo->ExceptionRecord->ExceptionCode);
            }
            return EXCEPTION_CONTINUE_SEARCH;
        }));

    // Create a thread to execute the target function
    // Pass nullptr as first argument to trigger access violation
    // after key is loaded but before HMAC initialization
    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)([](LPVOID ThreadParameter) -> DWORD {
                     ((void (*)(void *))startFn)(nullptr);
                     return 0;
                 }),
                 NULL, 0, NULL);

    // Wait for the key to be captured
    WaitForSingleObject(keyReadyEvent, INFINITE);
    CloseHandle(keyReadyEvent);

    // Print the captured key in hexadecimal format
    for (int i = 0; i < 16; i++)
        printf("%02x", key[i]);
    printf("\n");
}

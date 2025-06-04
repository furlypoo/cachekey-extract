#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include <shellapi.h>
#include <string.h>
#include <conio.h>
#include <winnt.h>
#include <winternl.h>
#include <stdbool.h>
#include <stdlib.h>
#include "Zydis.h"


static bool maskedCompare(const uint8_t *a, const uint8_t *b, const uint8_t *mask, int len)
{
    for (int i = 0; i < len; i++)
        if ((a[i] & mask[i]) != (b[i] & mask[i]))
            return false;
    return true;
}

LPVOID get_image_base_from_peb(HANDLE hProcess) {
    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength;

    // Get process basic information to get PEB address
    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation,
                                               &pbi, sizeof(pbi), &returnLength);
    if (status != 0) {
        return NULL;
    }

    // Read PEB
    PEB peb;
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead)) {
        return NULL;
    }

    return peb.Reserved3[1]; // ImageBaseAddress is at Reserved3[1] in MinGW's PEB structure
}

BOOL find_text_section(HANDLE hProcess, LPVOID* textAddr, SIZE_T* textSize) {
    // Get the image base address from PEB
    LPVOID imageBase = get_image_base_from_peb(hProcess);
    if (imageBase == NULL) {
        return FALSE;
    }

    // Read DOS header
    IMAGE_DOS_HEADER dosHeader;
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, imageBase, &dosHeader, sizeof(dosHeader), &bytesRead)) {
        return FALSE;
    }

    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        return FALSE;
    }

    // Read NT headers
    IMAGE_NT_HEADERS ntHeaders;
    LPVOID ntHeaderAddr = (LPVOID)((DWORD_PTR)imageBase + dosHeader.e_lfanew);
    if (!ReadProcessMemory(hProcess, ntHeaderAddr, &ntHeaders, sizeof(ntHeaders), &bytesRead)) {
        return FALSE;
    }

    if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }

    // Find .text section
    WORD numSections = ntHeaders.FileHeader.NumberOfSections;
    LPVOID sectionHeaderAddr = (LPVOID)((DWORD_PTR)ntHeaderAddr + sizeof(IMAGE_NT_HEADERS));

    for (WORD i = 0; i < numSections; i++) {
        IMAGE_SECTION_HEADER sectionHeader;
        LPVOID currentSectionAddr = (LPVOID)((DWORD_PTR)sectionHeaderAddr + (i * sizeof(IMAGE_SECTION_HEADER)));

        if (!ReadProcessMemory(hProcess, currentSectionAddr, &sectionHeader, sizeof(sectionHeader), &bytesRead)) {
            continue;
        }

        // Check if this is the .text section
        if (strcmp((char*)sectionHeader.Name, ".text") == 0) {
            *textAddr = (LPVOID)((DWORD_PTR)imageBase + sectionHeader.VirtualAddress);
            *textSize = sectionHeader.Misc.VirtualSize;
            return TRUE;
        }
    }

    return FALSE;
}

// Global variables for key extraction
static uint8_t extracted_key[16];
static HANDLE keyReadyEvent = NULL;
static volatile bool key_extracted = false;
static void (*target_function)(void*) = NULL;

// Structure to store pattern match information
typedef struct {
    SIZE_T offset;
    int reg_used;
} PatternMatch;

#define MAX_PATTERN_MATCHES 32
static PatternMatch pattern_matches[MAX_PATTERN_MATCHES];
static int num_pattern_matches = 0;

// Global pattern data for reuse across cycles
static uint8_t patterns[16][ZYDIS_MAX_INSTRUCTION_LENGTH * 3];
static uint8_t patternMasks[16][ZYDIS_MAX_INSTRUCTION_LENGTH * 3];
static int patternSizes[16];
static bool patterns_initialized = false;

void initialize_patterns(void) {
    if (patterns_initialized) return;
    
    memset(patterns, 0, sizeof(patterns));
    memset(patternMasks, 0xff, sizeof(patternMasks));
    memset(patternSizes, 0, sizeof(patternSizes));

    for (int reg = 0; reg < 16; reg++) {
        uint8_t *pattern = patterns[reg];
        uint8_t *patternMask = patternMasks[reg];
        ZydisEncoderRequest req;

        // Pattern 1: cmp dword ptr [reg], 48544658h  ; "XFTH"
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

        // Pattern 2: jnz (with wildcarded address)
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
        // Wildcard the jump address
        patternMask[-1] = 0;
        patternMask[-2] = 0;
        patternMask[-3] = 0;
        patternMask[-4] = 0;

        // Pattern 3: cmp dword ptr [reg+4], 9
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
    }
    
    patterns_initialized = true;
}

int search_for_patterns_in_buffer(BYTE* buffer, SIZE_T bufferSize) {
    initialize_patterns();
    num_pattern_matches = 0;
    
    for (SIZE_T i = 0; i + 999 < bufferSize && num_pattern_matches < MAX_PATTERN_MATCHES; i++) {
        for (int reg = 0; reg < 16; reg++) {
            if (maskedCompare(buffer + i, patterns[reg], patternMasks[reg], patternSizes[reg])) {
                pattern_matches[num_pattern_matches].offset = i;
                pattern_matches[num_pattern_matches].reg_used = reg;
                printf("Target pattern found at offset: 0x%llx (register %d)\n", (long long)i, reg);
                num_pattern_matches++;
                break; // Don't check other registers for the same offset
            }
        }
    }
    
    if (num_pattern_matches > 0) {
        printf("Found %d pattern matches total\n", num_pattern_matches);
    }
    
    return num_pattern_matches;
}

void disassemble_forward(void* start_addr, SIZE_T max_bytes, int max_instructions) {
    printf("\nDisassembly from 0x%p:\n", start_addr);
    printf("----------------------------------------\n");
    
    ZyanUSize offset = 0;
    ZydisDisassembledInstruction instruction;
    ZyanU64 runtime_address = (ZyanU64)start_addr;
    int instruction_count = 0;
    
    while (instruction_count < max_instructions && 
           offset < max_bytes &&
           ZYAN_SUCCESS(ZydisDisassembleIntel(
               ZYDIS_MACHINE_MODE_LONG_64,
               runtime_address,
               (ZyanU8*)start_addr + offset,
               max_bytes - offset,
               &instruction
           ))) {
        
        printf("%016llX  %s\n", runtime_address, instruction.text);
        
        offset += instruction.info.length;
        runtime_address += instruction.info.length;
        instruction_count++;
    }
    
    printf("----------------------------------------\n");
    printf("Disassembled %d instructions\n\n", instruction_count);
}

bool validate_key_entropy(const uint8_t* key) {
    int zero_count = 0;
    int ascii_count = 0;
    int repeated_bytes = 0;
    uint8_t byte_counts[256] = {0};
    
    // Count occurrences of each byte value
    for (int i = 0; i < 16; i++) {
        byte_counts[key[i]]++;
        
        // Count zeros
        if (key[i] == 0) zero_count++;
        
        // Count ASCII printable characters (0x20-0x7E)
        if (key[i] >= 0x20 && key[i] <= 0x7E) ascii_count++;
    }
    
    // Count bytes that appear more than once
    for (int i = 0; i < 256; i++) {
        if (byte_counts[i] > 1) {
            repeated_bytes += byte_counts[i] - 1;
        }
    }
    
    // Check for pointer-like patterns (4+ consecutive zero bytes, common in x64 pointers)
    int max_consecutive_zeros = 0;
    int current_consecutive_zeros = 0;
    for (int i = 0; i < 16; i++) {
        if (key[i] == 0) {
            current_consecutive_zeros++;
            if (current_consecutive_zeros > max_consecutive_zeros) {
                max_consecutive_zeros = current_consecutive_zeros;
            }
        } else {
            current_consecutive_zeros = 0;
        }
    }
    
    printf("Key validation: zeros=%d/16, ascii=%d/16, repeated=%d, max_consec_zeros=%d\n",
           zero_count, ascii_count, repeated_bytes, max_consecutive_zeros);
    
    // Heuristic rules for good crypto key:
    // - No more than 4 zero bytes (25%)
    // - No more than 8 ASCII bytes (50%) 
    // - No more than 4 repeated bytes total
    // - No more than 3 consecutive zeros (pointer pattern)
    if (zero_count > 4) {
        printf("Too many zero bytes (%d/16)\n", zero_count);
        return false;
    }
    
    if (ascii_count > 8) {
        printf("Too many ASCII bytes (%d/16) - might be text\n", ascii_count);
        return false;
    }
    
    if (repeated_bytes > 4) {
        printf("Too many repeated bytes (%d)\n", repeated_bytes);
        return false;
    }
    
    if (max_consecutive_zeros > 3) {
        printf("Too many consecutive zeros (%d) - might be pointer\n", max_consecutive_zeros);
        return false;
    }
    
    return true;
}

// Exception handler to capture the key
LONG WINAPI key_extraction_handler(PEXCEPTION_POINTERS ExceptionInfo) {
    printf("Exception caught: Code=0x%08X, Address=0x%p\n", 
           ExceptionInfo->ExceptionRecord->ExceptionCode,
           ExceptionInfo->ExceptionRecord->ExceptionAddress);
    
    // Disassemble around RIP to show what instruction caused the exception
    printf("\nDisassembly around exception RIP:\n");
    LPVOID rip_addr = (LPVOID)ExceptionInfo->ContextRecord->Rip;
    
    // Start from an aligned address 32 bytes before RIP
    LPVOID aligned_start = (LPVOID)(((DWORD_PTR)rip_addr - 32) & ~0xF);
    
    // Scan forward for a REX prefix to increase chance of instruction boundary
    LPVOID start_addr = aligned_start;
    for (int i = 0; i < 16; i++) {
        BYTE* byte_ptr = (BYTE*)aligned_start + i;
        if ((*byte_ptr & 0xF0) == 0x40) { // REX prefix check
            start_addr = (LPVOID)byte_ptr;
            printf("Found potential REX prefix at offset +%d from aligned start\n", i);
            break;
        }
    }
    
    disassemble_forward(start_addr, 128, 20);
    
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION) {
        printf("Access violation details: Type=%d, Address=0x%p\n",
               (int)ExceptionInfo->ExceptionRecord->ExceptionInformation[0],
               (void*)ExceptionInfo->ExceptionRecord->ExceptionInformation[1]);
        printf("Context: RIP=0x%llX, RSP=0x%llX, R8=0x%llX\n",
               ExceptionInfo->ContextRecord->Rip,
               ExceptionInfo->ContextRecord->Rsp,
               ExceptionInfo->ContextRecord->R8);
        
        // Print stack contents from RSP-0x20 forward for 0x100 bytes
        printf("\nStack dump (RSP-0x20 + 0x100 bytes):\n");
        LPVOID stack_start = (LPVOID)(ExceptionInfo->ContextRecord->Rsp - 0x20);
        for (int i = 0; i < 0x100; i += 16) {
            printf("%p: ", (BYTE*)stack_start + i);
            for (int j = 0; j < 16 && i + j < 0x100; j++) {
                printf("%02x ", *((BYTE*)stack_start + i + j));
            }
            printf("\n");
        }
        printf("\n");
        
        // Try RSP+0x20 first, then fallback to R8
        LPVOID key_ptr = (LPVOID)(ExceptionInfo->ContextRecord->Rsp + 0x20);
        printf("Trying RSP+0x20 (0x%p) for key location\n", key_ptr);
        
        // Check if RSP+0x20 points to readable memory
        MEMORY_BASIC_INFORMATION mbi;
        SIZE_T result = VirtualQuery(key_ptr, &mbi, sizeof(mbi));
        
        if (result == 0) {
            printf("VirtualQuery failed for RSP+0x20 address 0x%p (error %d)\n", 
                   key_ptr, GetLastError());
        } else {
            printf("RSP+0x20 memory info: Base=0x%p, Size=0x%X, State=0x%X, Protect=0x%X, Type=0x%X\n",
                   mbi.BaseAddress, (DWORD)mbi.RegionSize, mbi.State, mbi.Protect, mbi.Type);
            
            // Check if memory is committed and readable
            if (mbi.State == MEM_COMMIT && 
                (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) &&
                ((DWORD_PTR)key_ptr + 16 <= (DWORD_PTR)mbi.BaseAddress + mbi.RegionSize)) {
                
                printf("RSP+0x20 points to valid readable memory - extracting key\n");
                memcpy(extracted_key, key_ptr, 16);
                
                // Validate key looks like random crypto material
                if (validate_key_entropy(extracted_key)) {
                    printf("Key validation passed - looks like crypto material\n");
                    key_extracted = true;
                    if (keyReadyEvent) {
                        SetEvent(keyReadyEvent);
                    }
                    SuspendThread(GetCurrentThread());
                    return EXCEPTION_CONTINUE_SEARCH;
                } else {
                    printf("RSP+0x20 key validation failed - doesn't look like crypto material\n");
                }
            } else {
                printf("RSP+0x20 does not point to valid readable memory\n");
            }
        }
        
        // Fallback to R8 if RSP+0x20 didn't work
        printf("Trying R8 (0x%llX) for key location\n", ExceptionInfo->ContextRecord->R8);
        key_ptr = (LPVOID)ExceptionInfo->ContextRecord->R8;
        result = VirtualQuery(key_ptr, &mbi, sizeof(mbi));
        
        if (result == 0) {
            printf("VirtualQuery failed for R8 address 0x%llX (error %d) - both RSP+0x20 and R8 failed\n", 
                   ExceptionInfo->ContextRecord->R8, GetLastError());
            return EXCEPTION_CONTINUE_SEARCH;
        }
        
        printf("R8 memory info: Base=0x%p, Size=0x%X, State=0x%X, Protect=0x%X, Type=0x%X\n",
               mbi.BaseAddress, (DWORD)mbi.RegionSize, mbi.State, mbi.Protect, mbi.Type);
        
        // Check if memory is committed and readable
        if (mbi.State != MEM_COMMIT || 
            !(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
            printf("R8 does not point to readable memory - both RSP+0x20 and R8 failed\n");
            return EXCEPTION_CONTINUE_SEARCH;
        }
        
        // Verify we can read at least 16 bytes
        if ((DWORD_PTR)key_ptr + 16 > (DWORD_PTR)mbi.BaseAddress + mbi.RegionSize) {
            printf("R8 region too small for 16-byte key - both RSP+0x20 and R8 failed\n");
            return EXCEPTION_CONTINUE_SEARCH;
        }
        
        printf("R8 points to valid readable memory - extracting key\n");
        
        // At this point, R8 contains pointer to the key buffer
        memcpy(extracted_key, key_ptr, 16);
        
        // Validate key looks like random crypto material
        if (validate_key_entropy(extracted_key)) {
            printf("Key validation passed - looks like crypto material\n");
            key_extracted = true;
            if (keyReadyEvent) {
                SetEvent(keyReadyEvent);
            }
            SuspendThread(GetCurrentThread()); // Suspend thread to prevent exception propagation
        } else {
            printf("Key validation failed - doesn't look like crypto material, continuing...\n");
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// Thread function to execute the target function
DWORD WINAPI execute_target_function(LPVOID param) {
    // Fill the stack below our frame with 0xf0 for debugging
    BYTE* current_rsp;
    __asm__ volatile ("movq %%rsp, %0" : "=r" (current_rsp));
    
    // Fill 0x1000 bytes below current RSP with 0xf0
    memset(current_rsp - 0x1000, 0xf0, 0x1000);
    
    target_function(NULL); // Pass NULL to trigger access violation after key is loaded
    return 0;
}

bool copy_pe_image_to_local_memory(HANDLE hProcess, LPVOID* localImageBase, SIZE_T* imageSize) {
    // Get the image base address from PEB
    LPVOID remoteImageBase = get_image_base_from_peb(hProcess);
    if (!remoteImageBase) {
        printf("Failed to get remote image base address\n");
        return false;
    }

    // Read DOS header to get image size
    IMAGE_DOS_HEADER dosHeader;
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, remoteImageBase, &dosHeader, sizeof(dosHeader), &bytesRead)) {
        printf("Failed to read DOS header\n");
        return false;
    }

    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Invalid DOS signature\n");
        return false;
    }

    // Read NT headers to get image size
    IMAGE_NT_HEADERS ntHeaders;
    LPVOID ntHeaderAddr = (LPVOID)((DWORD_PTR)remoteImageBase + dosHeader.e_lfanew);
    if (!ReadProcessMemory(hProcess, ntHeaderAddr, &ntHeaders, sizeof(ntHeaders), &bytesRead)) {
        printf("Failed to read NT headers\n");
        return false;
    }

    if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
        printf("Invalid NT signature\n");
        return false;
    }

    *imageSize = ntHeaders.OptionalHeader.SizeOfImage;

    // Allocate executable memory for the entire image
    *localImageBase = VirtualAlloc(NULL, *imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!*localImageBase) {
        printf("Failed to allocate local memory for PE image\n");
        return false;
    }

    // Copy the entire image
    if (!ReadProcessMemory(hProcess, remoteImageBase, *localImageBase, *imageSize, &bytesRead)) {
        printf("Failed to copy PE image to local memory\n");
        VirtualFree(*localImageBase, 0, MEM_RELEASE);
        return false;
    }

    printf("Copied PE image: 0x%p -> 0x%p (size: 0x%X)\n",
           remoteImageBase, *localImageBase, (DWORD)*imageSize);

    return true;
}

bool extract_cache_key_from_match(HANDLE hProcess, LPVOID localImageBase, SIZE_T imageSize, int match_index) {
    if (match_index >= num_pattern_matches) {
        return false;
    }
    
    PatternMatch* match = &pattern_matches[match_index];
    char* found = (char*)localImageBase + match->offset;
    
    printf("Trying extraction from match %d (offset 0x%llx, register %d)\n", 
           match_index + 1, (long long)match->offset, match->reg_used);

    // Show disassembly of the area around this match
    disassemble_forward(found, 1000, 50);

    // Disassemble forward to find the call instruction
    void *startFn = NULL;
    ZydisDisassembledInstruction inst;
    LPVOID currentAddr = found;

    while (ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, (ZyanU64)currentAddr, currentAddr, 999, &inst))) {
        if (inst.info.mnemonic == ZYDIS_MNEMONIC_CALL) {
            ZydisCalcAbsoluteAddress(&inst.info, &inst.operands[0], (ZyanU64)currentAddr, (ZyanU64 *)&startFn);
            printf("Target function found at: 0x%p\n", startFn);
            break;
        }
        currentAddr = (LPVOID)((DWORD_PTR)currentAddr + inst.info.length);
    }

    if (!startFn) {
        printf("Could not find target function call for this match\n");
        return false;
    }

    // Show disassembly of the target function
    printf("\nTarget function disassembly:\n");
    disassemble_forward(startFn, 1000, 50);

    // Set up exception handling and execute the function
    keyReadyEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    key_extracted = false;

    PVOID handler = AddVectoredExceptionHandler(1, key_extraction_handler);

    // Set the global target function pointer and create thread to execute it
    target_function = (void(*)(void*))startFn;
    HANDLE thread = CreateThread(NULL, 0, execute_target_function, NULL, 0, NULL);

    // Wait for key extraction
    DWORD waitResult = WaitForSingleObject(keyReadyEvent, 500); // 500ms timeout

    RemoveVectoredExceptionHandler(handler);
    CloseHandle(keyReadyEvent);

    if (waitResult == WAIT_OBJECT_0 && key_extracted) {
        printf("Extracted key: ");
        for (int i = 0; i < 16; i++) {
            printf("%02x", extracted_key[i]);
        }
        printf("\n");

        // Write key to file
        FILE* keyFile = fopen("dbcachekey.txt", "w");
        if (keyFile) {
            for (int i = 0; i < 16; i++) {
                fprintf(keyFile, "%02x", extracted_key[i]);
            }
            fprintf(keyFile, "\n");
            fclose(keyFile);
            printf("Key written to dbcachekey.txt\n");
        } else {
            printf("Failed to write key to file\n");
        }

        return true;
    } else {
        printf("Key extraction timed out or failed for this match\n");
        return false;
    }
}

bool extract_cache_key(HANDLE hProcess, BYTE* textData, SIZE_T textSize) {
    // Copy entire PE image to local memory first
    LPVOID localImageBase;
    SIZE_T imageSize;
    if (!copy_pe_image_to_local_memory(hProcess, &localImageBase, &imageSize)) {
        return false;
    }

    // Search for all pattern matches in the local image copy
    int matches_found = search_for_patterns_in_buffer((BYTE*)localImageBase, imageSize);
    
    if (matches_found == 0) {
        printf("No patterns found in image\n");
        VirtualFree(localImageBase, 0, MEM_RELEASE);
        return false;
    }

    // Try extraction from each match until one succeeds
    for (int i = 0; i < matches_found; i++) {
        printf("\n--- Trying match %d of %d ---\n", i + 1, matches_found);
        
        if (extract_cache_key_from_match(hProcess, localImageBase, imageSize, i)) {
            // Clean up local image copy
            VirtualFree(localImageBase, 0, MEM_RELEASE);
            return true;
        }
    }

    printf("All %d pattern matches failed to extract key\n", matches_found);
    
    // Clean up local image copy
    VirtualFree(localImageBase, 0, MEM_RELEASE);
    return false;
}

int get_env_int(const char* env_name, int default_value, int min_value, int max_value) {
    char* env_value = getenv(env_name);
    if (env_value == NULL) {
        return default_value;
    }
    
    int value = atoi(env_value);
    if (value < min_value || value > max_value) {
        printf("Warning: %s value %d is out of range [%d, %d], using default %d\n", 
               env_name, value, min_value, max_value, default_value);
        return default_value;
    }
    
    return value;
}

int main(int argc, char* argv[]) {
    LPWSTR* argv_w;
    int argc_w;

    argv_w = CommandLineToArgvW(GetCommandLineW(), &argc_w);
    if (argv_w == NULL) {
        printf("Failed to parse command line\n");
        return 1;
    }

    printf("argc: %d\n", argc_w);

    if (argc_w < 2) {
        printf("Usage: program.exe <executable_path>\n");
        LocalFree(argv_w);
        return 1;
    }

    // Convert wide string to narrow string
    char target_exe[MAX_PATH];
    WideCharToMultiByte(CP_ACP, 0, argv_w[1], -1, target_exe, MAX_PATH, NULL, NULL);

    STARTUPINFO si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    // Create process in suspended state
    if (!CreateProcess(NULL, target_exe, NULL, NULL, FALSE,
                      CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("CreateProcess failed (%d)\n", GetLastError());
        LocalFree(argv_w);
        return 1;
    }

    printf("Process created with PID: %d\n", pi.dwProcessId);
    
    // Get configuration from environment variables
    int max_extraction_attempts = get_env_int("WOWT_MAX_EXTRACTION_ATTEMPTS", 5, 1, 20);
    int cycle_runtime_ms = get_env_int("WOWT_CYCLE_RUNTIME_MS", 15, 1, 1000);
    
    printf("Configuration:\n");
    printf("  Max extraction attempts: %d (WOWT_MAX_EXTRACTION_ATTEMPTS)\n", max_extraction_attempts);
    printf("  Cycle runtime (ms): %d (WOWT_CYCLE_RUNTIME_MS)\n", cycle_runtime_ms);
    printf("Press any key to stop monitoring...\n\n");

    int cycle = 0;
    LPVOID textAddr;
    SIZE_T textSize;
    bool pattern_found = false;
    int cycles_since_pattern = 0;
    int extraction_attempts = 0;

    // Main monitoring loop - checks for target pattern at each cycle
    while (1) {
        cycle++;

        // Check if process is still alive
        DWORD exitCode;
        if (GetExitCodeProcess(pi.hProcess, &exitCode) && exitCode != STILL_ACTIVE) {
            printf("Process exited with code %d after %d cycles\n", exitCode, cycle - 1);
            break;
        }

        // Resume for configured duration
        ResumeThread(pi.hThread);
        Sleep(cycle_runtime_ms);

        // Suspend again
        SuspendThread(pi.hThread);

        // Find .text section
        if (find_text_section(pi.hProcess, &textAddr, &textSize)) {
            // Read the .text section
            BYTE* buffer = malloc(textSize);
            if (buffer) {
                SIZE_T bytesRead;
                if (ReadProcessMemory(pi.hProcess, textAddr, buffer, textSize, &bytesRead)) {
                    printf("Cycle %d: .text at 0x%p (size: 0x%X)\n",
                           cycle, textAddr, (DWORD)textSize);

                    // Check for target patterns in the text section
                    int current_matches_found = search_for_patterns_in_buffer(buffer, bytesRead);
                    
                    if (current_matches_found > 0 && !pattern_found) {
                        printf("\nTarget patterns detected for the first time!\n");
                        pattern_found = true;
                        cycles_since_pattern = 0;
                    }
                    
                    if (pattern_found) {
                        cycles_since_pattern++;
                        extraction_attempts++;
                        
                        printf("\nAttempt %d: Beginning key extraction (cycle %d, %d cycles since pattern)...\n", 
                               extraction_attempts, cycle, cycles_since_pattern);

                        // Extract key from the process using the same logic as DBCacheKeyExtractor
                        if (extract_cache_key(pi.hProcess, buffer, bytesRead)) {
                            printf("Key extraction successful!\n");
                            break;
                        } else {
                            printf("Key extraction failed. ");
                            if (extraction_attempts < max_extraction_attempts) {
                                printf("Continuing execution to allow dependent functions to unpack...\n");
                            } else {
                                printf("Maximum extraction attempts reached.\n");
                                break;
                            }
                        }
                        
                        // Stop if we've reached max attempts
                        if (extraction_attempts >= max_extraction_attempts) {
                            break;
                        }
                    }
                } else {
                    printf("Cycle %d: Failed to read .text section (error %d)\n", cycle, GetLastError());
                }
                free(buffer);
            } else {
                printf("Cycle %d: Failed to allocate buffer\n", cycle);
            }
        } else {
            printf("Cycle %d: Could not find .text section\n", cycle);
        }

        // Check if user wants to stop
        if (_kbhit()) {
            break;
        }
    }

    printf("\nStopping monitoring...\n");

    // Clean up
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    LocalFree(argv_w);

    return 0;
}
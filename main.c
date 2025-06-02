#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include <shellapi.h>
#include <string.h>
#include <math.h>
#include <conio.h>
#include <winnt.h>
#include <winternl.h>
#include <stdbool.h>
#include "Zydis.h"

double calculate_shannon_entropy(BYTE* data, SIZE_T size) {
    if (size == 0) return 0.0;
    
    // Count frequency of each byte value
    DWORD freq[256] = {0};
    for (SIZE_T i = 0; i < size; i++) {
        freq[data[i]]++;
    }
    
    // Calculate Shannon entropy
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = (double)freq[i] / size;
            entropy -= p * log2(p);
        }
    }
    
    return entropy;
}

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
    
    return peb.ImageBaseAddress;
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

// Exception handler to capture the key
LONG WINAPI key_extraction_handler(PEXCEPTION_POINTERS ExceptionInfo) {
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION) {
        // At this point, R8 contains pointer to the key buffer
        memcpy(extracted_key, (void *)ExceptionInfo->ContextRecord->R8, 16);
        key_extracted = true;
        if (keyReadyEvent) {
            SetEvent(keyReadyEvent);
        }
        SuspendThread(GetCurrentThread()); // Suspend thread to prevent exception propagation
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// Thread function to execute the target function
DWORD WINAPI execute_target_function(LPVOID param) {
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

bool extract_cache_key(HANDLE hProcess, BYTE* textData, SIZE_T textSize) {
    // Copy entire PE image to local memory first
    LPVOID localImageBase;
    SIZE_T imageSize;
    if (!copy_pe_image_to_local_memory(hProcess, &localImageBase, &imageSize)) {
        return false;
    }
    // Create search patterns for each register (same logic as original extractor)
    uint8_t patterns[16][ZYDIS_MAX_INSTRUCTION_LENGTH * 3];
    memset(patterns, 0, sizeof(patterns));
    uint8_t patternMasks[16][ZYDIS_MAX_INSTRUCTION_LENGTH * 3];
    memset(patternMasks, 0xff, sizeof(patternMasks));
    int patternSizes[16];
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

    // Search for the pattern in the local image copy
    char *found = NULL;
    for (int i = 0; i + 999 < imageSize; i++) {
        for (int reg = 0; reg < 16; reg++) {
            if (maskedCompare((uint8_t*)localImageBase + i, patterns[reg], patternMasks[reg], patternSizes[reg])) {
                found = (char *)localImageBase + i;
                printf("Pattern found at offset: 0x%llx\n", (long long)i);
                break;
            }
        }
        if (found) break;
    }
    
    if (!found) {
        printf("Pattern not found in image\n");
        VirtualFree(localImageBase, 0, MEM_RELEASE);
        return false;
    }

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
        printf("Could not find target function call\n");
        VirtualFree(localImageBase, 0, MEM_RELEASE);
        return false;
    }

    // Set up exception handling and execute the function
    keyReadyEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    key_extracted = false;
    
    PVOID handler = AddVectoredExceptionHandler(1, key_extraction_handler);
    
    // Set the global target function pointer and create thread to execute it
    target_function = (void(*)(void*))startFn;
    HANDLE thread = CreateThread(NULL, 0, execute_target_function, NULL, 0, NULL);

    // Wait for key extraction
    DWORD waitResult = WaitForSingleObject(keyReadyEvent, 5000); // 5 second timeout
    
    RemoveVectoredExceptionHandler(handler);
    CloseHandle(keyReadyEvent);
    
    // Clean up local image copy
    VirtualFree(localImageBase, 0, MEM_RELEASE);
    
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
        printf("Key extraction timed out or failed\n");
        return false;
    }
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
    printf("Press any key to stop monitoring...\n\n");
    
    int cycle = 0;
    LPVOID textAddr;
    SIZE_T textSize;
    
    // Main monitoring loop
    while (1) {
        cycle++;
        
        // Check if process is still alive
        DWORD exitCode;
        if (GetExitCodeProcess(pi.hProcess, &exitCode) && exitCode != STILL_ACTIVE) {
            printf("Process exited with code %d after %d cycles\n", exitCode, cycle - 1);
            break;
        }
        
        // Resume for 15ms
        ResumeThread(pi.hThread);
        Sleep(15);
        
        // Suspend again
        SuspendThread(pi.hThread);
        
        // Find .text section
        if (find_text_section(pi.hProcess, &textAddr, &textSize)) {
            // Read the .text section
            BYTE* buffer = malloc(textSize);
            if (buffer) {
                SIZE_T bytesRead;
                if (ReadProcessMemory(pi.hProcess, textAddr, buffer, textSize, &bytesRead)) {
                    // Calculate Shannon entropy
                    double entropy = calculate_shannon_entropy(buffer, bytesRead);
                    
                    printf("Cycle %d: .text at 0x%p (size: 0x%X) - Shannon Entropy: %.6f\n", 
                           cycle, textAddr, (DWORD)textSize, entropy);
                    
                    // Check if entropy has dropped below threshold (self-extraction complete)
                    if (entropy < 6.85) {
                        printf("\nEntropy dropped below 6.85 - self-extraction detected!\n");
                        printf("Beginning key extraction...\n");
                        
                        // Extract key from the process using the same logic as DBCacheKeyExtractor
                        if (extract_cache_key(pi.hProcess, buffer, bytesRead)) {
                            printf("Key extraction successful!\n");
                        } else {
                            printf("Key extraction failed.\n");
                        }
                        
                        break;
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
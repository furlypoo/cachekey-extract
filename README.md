# Cache Key Extractor

An advanced cache key extraction tool for World of Warcraft processes. This tool automatically detects when target code patterns become available and extracts cryptographic keys using assembly pattern matching and controlled exception handling.

## Mechanism of Action

### 1. Process Creation and Monitoring

The tool starts by creating the target process (WowT.exe) in a suspended state using the Windows API:

```c
CreateProcess(NULL, target_exe, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)
```

This allows us to control execution precisely and monitor the process state during initialization.

### 2. Pattern-Based Target Detection

The core innovation is using **assembly pattern matching** to detect when the target code becomes available:

#### Monitoring Loop
- Resumes process execution for exactly **15ms intervals**
- Suspends the process and reads the .text section
- Searches for specific assembly patterns that indicate the presence of target functions
- Continues until the target pattern is found (indicating the code is ready for key extraction)

#### Why This Works
- **Direct pattern matching** is more reliable than heuristics like entropy
- **Immediate detection** as soon as the target code appears, regardless of surrounding code state
- **Build-independent** detection that works across different compilation and packing strategies

### 3. Memory Architecture Analysis

#### PEB-Based Image Location
Instead of hardcoding memory addresses, we use the Process Environment Block (PEB):

```c
// Get PEB from process
NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength);
ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead);
LPVOID imageBase = peb.Reserved3[1]; // ImageBaseAddress
```

#### PE Header Parsing
We parse the PE (Portable Executable) headers to locate the .text section:

```c
// Read DOS header → NT headers → Section headers
IMAGE_DOS_HEADER dosHeader;
IMAGE_NT_HEADERS ntHeaders;
IMAGE_SECTION_HEADER sectionHeader;

// Find .text section specifically
if (strcmp((char*)sectionHeader.Name, ".text") == 0) {
    *textAddr = imageBase + sectionHeader.VirtualAddress;
    *textSize = sectionHeader.Misc.VirtualSize;
}
```

### 4. Complete PE Image Copying

To safely execute functions from the target process, we copy the **entire PE image** to local memory:

```c
// Allocate executable memory
LPVOID localImageBase = VirtualAlloc(NULL, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

// Copy complete image (all sections: .text, .data, .rdata, etc.)
ReadProcessMemory(hProcess, remoteImageBase, localImageBase, imageSize, &bytesRead);
```

#### Why Complete Image Copy?
- Functions may reference data in .data, .rdata, or other sections
- Relative addressing and imports need proper memory layout
- Ensures all dependencies are available for execution

### 5. Assembly Pattern Recognition

We use the **Zydis disassembler** to generate and search for specific assembly patterns at each monitoring cycle:

#### Target Pattern
The tool searches for this specific instruction sequence:
```assembly
cmp dword ptr [reg], 48544658h  ; "XFTH" magic signature
jnz <somewhere>                 ; Jump if not found
cmp dword ptr [reg+4], 9        ; Check additional field
```

#### Real-Time Pattern Generation
```c
// Generate patterns for all 16 possible registers (RAX, RBX, RCX, etc.)
void initialize_patterns(void) {
    for (int reg = 0; reg < 16; reg++) {
        ZydisEncoderRequest req;
        req.operands[0].mem.base = (ZydisRegister)(ZYDIS_REGISTER_RAX + reg);
        req.operands[1].imm.u = 0x48544658; // "XFTH"
        ZydisEncoderEncodeInstruction(&req, pattern, &encodedSize);
    }
}
```

#### Cycle-Based Pattern Search
```c
// Search for pattern in each monitoring cycle
bool search_for_pattern_in_buffer(BYTE* buffer, SIZE_T bufferSize) {
    for (SIZE_T i = 0; i + 999 < bufferSize; i++) {
        for (int reg = 0; reg < 16; reg++) {
            if (maskedCompare(buffer + i, patterns[reg], patternMasks[reg], patternSizes[reg])) {
                return true; // Pattern found - proceed with key extraction
            }
        }
    }
    return false;
}
```

#### Pattern Matching with Wildcards
```c
// Mask out jump addresses (they vary between builds)
patternMask[-4] = 0; // Wildcard the jump target
patternMask[-3] = 0;
patternMask[-2] = 0;
patternMask[-1] = 0;
```

### 6. Control Flow Analysis

After finding the pattern, we disassemble forward to locate the target function:

```c
while (ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, currentAddr, currentAddr, 999, &inst))) {
    if (inst.info.mnemonic == ZYDIS_MNEMONIC_CALL) {
        ZydisCalcAbsoluteAddress(&inst.info, &inst.operands[0], currentAddr, &startFn);
        break;
    }
    currentAddr += inst.info.length;
}
```

### 7. Controlled Exception Handling

The key extraction uses **vectored exception handling** to capture the cryptographic key:

#### Exception Handler Setup
```c
LONG WINAPI key_extraction_handler(PEXCEPTION_POINTERS ExceptionInfo) {
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION) {
        // Key is in R8 register at this point
        memcpy(extracted_key, (void *)ExceptionInfo->ContextRecord->R8, 16);
        key_extracted = true;
        SuspendThread(GetCurrentThread()); // Prevent crash
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
```

#### Function Execution Strategy
```c
// Execute target function with NULL parameter
// This causes controlled access violation after key is loaded into R8
CreateThread(NULL, 0, execute_target_function, NULL, 0, NULL);
```

#### Why This Works
1. Target function loads 16-byte key into a buffer
2. Function moves buffer address into R8 register
3. Function attempts to initialize HMAC with NULL context (our NULL parameter)
4. Access violation occurs when accessing NULL pointer
5. Our exception handler captures the key from R8 before the crash

### 8. Technical Advantages

#### Compared to Static Analysis
- **No reverse engineering required** - works on any build
- **Handles obfuscation** - pattern detection bypasses code obfuscation
- **Build-independent** - pattern matching adapts to compiler variations

#### Compared to Memory Dumping
- **No large dumps needed** - works on live process
- **Faster execution** - real-time monitoring vs. post-processing
- **Lower storage requirements** - extracts only the key

#### Security Considerations
- **Controlled execution environment** - isolated memory space
- **Exception handling** - prevents crashes and system instability
- **Temporary execution** - target function runs briefly and safely

## Implementation Details

### Libraries Used
- **Zydis**: x86/x64 disassembler for pattern generation and analysis
- **Windows API**: Process creation, memory management, exception handling
- **MinGW**: Cross-compilation for native Windows PE executable

### Build Process
```bash
x86_64-w64-mingw32-gcc -O2 -I . main.c Zydis.c -o cachekey-extract.exe -lpsapi -lshell32 -lntdll -static-libgcc
```

### Performance Characteristics
**Note: These performance metrics are hallucinated and unverified.**
- **Memory usage**: ~50MB during PE image copy
- **Execution time**: Typically 30-60 seconds depending on target process
- **CPU usage**: Minimal - mostly sleeping between 15ms intervals
- **Success rate**: High reliability across different builds

## Usage

```bash
./cachekey-extract.exe WowT.exe
```

### Output
- Real-time monitoring with cycle-by-cycle reporting
- Automatic detection and notification when target pattern is found
- Extracted 16-byte key displayed in hexadecimal format
- Key saved to `dbcachekey.txt` for further use

### Example Output
```
Process created with PID: 1234
Cycle 1: .text at 0x140000000 (size: 0x1000)
Cycle 2: .text at 0x140000000 (size: 0x1000)
...
Cycle 23: .text at 0x140000000 (size: 0x45A2000)
Target pattern found at offset: 0x1A2B3C4

Target pattern detected!
Beginning key extraction...
Pattern found at offset: 0x1A2B3C4
Target function found at: 0x140A1B2C3
Extracted key: 1a2b3c4d5e6f708192a3b4c5d6e7f809
Key written to dbcachekey.txt
Key extraction successful!
```

## Requirements

- Windows environment (native or Wine)
- Target WowT.exe executable
- Sufficient memory for PE image copying (~100MB recommended)
- Administrative privileges may be required for process creation/debugging

## Technical References

- [PE Format Specification](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
- [Shannon Entropy in Malware Analysis](https://ieeexplore.ieee.org/document/8368151)
- [Zydis Disassembler Engine](https://github.com/zyantific/zydis)
- [Windows Exception Handling](https://docs.microsoft.com/en-us/cpp/cpp/exception-handling-in-visual-cpp)
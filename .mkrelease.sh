#!/bin/bash

gh release create v1.0.0 --title "WowT Cache Key Extractor v1.0.0" --notes "# WowT Cache Key Extractor v1.0.0

## Features
- **Entropy-based Detection**: Monitors Shannon entropy of WoW process .text section every 15ms
- **Automatic Extraction**: Detects self-extraction when entropy drops below 6.85 threshold  
- **Advanced Pattern Matching**: Uses Zydis disassembler to find assembly patterns in extracted code
- **Reliable Memory Access**: Uses PEB to locate image base address correctly
- **Safe Function Execution**: Copies complete PE image to local memory for safe execution
- **Exception Handling**: Captures cache key from R8 register during controlled access violation
- **File Output**: Saves extracted key to both console and \`dbcachekey.txt\` file

## Usage
\`\`\`bash
./wowt-extract.exe WowT.exe
\`\`\`

The program will:
1. Monitor the target process entropy in real-time
2. Wait for self-extraction to complete (entropy < 6.85)
3. Automatically extract the 16-byte cache key
4. Output the key in hexadecimal format

## Technical Details
- Uses Windows PEB (Process Environment Block) for reliable image base detection
- Implements complete PE image copying with executable permissions
- Integrates Zydis disassembly engine for pattern recognition
- Employs vectored exception handling for safe key capture
- Supports live process analysis without requiring memory dumps

## Requirements
- Windows environment (tested with Wine)
- Target WowT.exe process to analyze

This tool eliminates the need for manual memory dumping by working directly with live processes."
cachekey-extract.exe: main.c Zydis.c
	x86_64-w64-mingw32-gcc -O2 -I . main.c Zydis.c -o cachekey-extract.exe -lpsapi -lshell32 -lntdll -static-libgcc

# Alias for backwards compatibility
main.exe: cachekey-extract.exe

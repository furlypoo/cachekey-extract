cachekey-extract.exe: main.c Zydis.c
	winegcc -mno-cygwin -Wb,--subsystem=console -I . main.c Zydis.c -o cachekey-extract.exe -lpsapi -lshell32

# Alias for backwards compatibility
main.exe: cachekey-extract.exe

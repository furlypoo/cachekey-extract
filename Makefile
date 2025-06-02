main.exe: main.c Zydis.c
	winegcc -mno-cygwin -Wb,--subsystem=console -I . main.c Zydis.c -o main.exe -lpsapi -lshell32

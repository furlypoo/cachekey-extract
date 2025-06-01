main.exe: main.c
	winegcc -mno-cygwin -Wb,--subsystem=windows main.c -o main.exe

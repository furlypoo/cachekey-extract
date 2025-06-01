#include <windows.h>

int WINAPI WinMain(HINSTANCE hInstance,
	 	   HINSTANCE hPrevInstance,
	    	   LPSTR     lpCmdLine,
		   int       nShowCmd)
{
	HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);

	DWORD _unused;
	WriteConsole(hStdout, TEXT("Blah!"), 5, &_unused, NULL);

	return 0;
}

#pragma warning(disable:4996)
#include <stdio.h> 
#include<string.h>
#include "PeView.h"

#define maxsize 1000

int main(int argc, char* argv[])
{   
	char  filename[245];
	if (argc == 1) {
		fputs("argv error\n", stderr);
		exit(1);
	}
	else {
		strcpy_s(filename, sizeof(filename) / sizeof(char), argv[1]);
	}
	inipe(filename);
	SetDosHeader();
	ShowDosHeader();
	ShowDosStopCode();
	SetNtHeader();
	ShowNtHeader();
	return(0);
	}
	

		
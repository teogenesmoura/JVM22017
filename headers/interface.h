#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <ctype.h>

#include "../headers/exibidor.h"
// #include "../headers/leitor.h"

#ifndef INTERFACE
	#define INTERFACE

	#ifdef INTERFACE_SERVER
		#define EXT_INTERFACE
	#else
		#define EXT_INTERFACE extern
	#endif

	EXT_INTERFACE int error_missingFile();
	EXT_INTERFACE int error_openFile();
	EXT_INTERFACE bool callFunc(FILE *fp);
	EXT_INTERFACE int menu_interface();
#endif
#include <stdbool.h>
#include <stdio.h>
#include "../headers/interface.h"
#include "../headers/leitor.h"

/* Variaveis globais */
/* Variavel global */
cFile classFile;
int main (int argc, char *argv[]){

	bool True = true;
	int ret;
	// extern cFile class_file;
	/*Verifica se o arquivo foi passado*/
	if(argc != 2)
		ret = error_missingFile();

	FILE *fp = fopen(argv[1], "rb");
	
	if(fp == NULL){
		ret = error_openFile();
		return ret;
	}

	init_leitor(fp);
	
	while(True) 
		True = callFunc(fp);

	// fclose(fp);
	printf("\n\n");
	return 0;

}
#include <stdbool.h>
#include <stdio.h>
#include "../headers/interface.h"
#include "../headers/leitor.h"
#include "../headers/instructions.h"

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

	/* Configuracoes iniciais para a inicializacao do programa... */
	mount_inst_array(decode);
	init_leitor(fp);
	
	while(True) 
		True = callFunc(fp);

	// fclose(fp);
	printf("\n\n");
	return 0;

}
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include "../headers/carregador.h"
#include "../headers/exibidor.h"
#include "../headers/leitor.h"
#include "../headers/interface.h"
#include "../headers/frame.h"
#include "../headers/instructions.h"

int main (int argc, char *argv[]){
    //bool True = true;
	int ret, opcao;
	// extern cFile class_file;
	/*Verifica se o arquivo foi passado*/
	if(argc < 2)
		ret = error_missingFile();
    if(argc < 3){
        printf("\n\tExibir .class [1]");
        printf("\tExecutar JVM [2]\n");
        scanf("%d", &opcao);
    }else{
          opcao = atoi(argv[2]);
    }
    printf("\n");
	FILE *fp = fopen(argv[1], "rb");
	
	if(fp == NULL){
		ret = error_openFile();
		getchar();
		exit(0);
		return ret;
	}

	mount_inst_array(decode);
	init_leitor(fp);
	if(opcao == 1){
       show_info();
    }else{
         if(opcao == 2){
             initStackFrame();
         }
    }

	
	printf("\n\n");
	return 0;
}

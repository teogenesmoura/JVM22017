#define INTERFACE_SERVER
#include "../headers/interface.h"
#include "../headers/frame.h"
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <ctype.h>
#include "../headers/leitor.h"
// #include "../headers/carregador.h"

int menu_interface(){
	
	char type[100] = "0";

	printf("\n\n\n");
	printf("\t++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
	printf("\t+ [1] - Exibir informações                             +\n");
	printf("\t+ [2] - Executar JVM                                   +\n");
	printf("\t+ [3] - Teste Carregador.                              +\n");
	printf("\t+ [4] - Sair.                                          +\n");
	printf("\t++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
	
	while ((strcmp(type,"1") != 0) && (strcmp(type,"2") != 0) && (strcmp(type,"3") != 0) && (strcmp(type,"4") != 0)){
		printf("\n\t\t>> Escolha uma das opções acima.<<: ");
		scanf("%[^\n]s", type);
		getchar();
	}

	return atoi(type);
}

bool callFunc(FILE *fp){

	int type = menu_interface();
	switch (type){
		case 1:
			show_info();
			break;
		case 2:
			initStackFrame();
			//roda jvm
			break;
		case 3:
			printf("AINDA NÃO PRONTO...CALMAAEE.\n");
			return false;
		case 4:
			return false;
		default:
			printf("Erro na escolha da opçao.\n");
			break;
	}
	printf("\n\n\t\t[>>> Aperte ENTER para continuar <<<]\n");

	getchar();
	return true;
}

int error_missingFile(){
	printf("ERRO: deve ser passado um argumento!\n");
	printf("Execute com:[program_name] [arquivo.class]\n");
	return MISSING_ARGUMENT;
}

int error_openFile(){
	printf("ERRO: não foi possivel abrir o arquivo .class.\n");
	return CANT_OPEN;
}

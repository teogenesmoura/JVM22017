
/****************************************************************************
** MEMBROS:                                                                **
**		Aluno 1: Jean Pierre Sissé                                         **
**		Aluno 2:                                                           **
**		Aluno 3:                                                           **
**		Aluno 4:                                                           **
**		Aluno 5:                                                           **
**                                                                         **
** Descrição: Lietor de arquivo .class                                     **
**compile com: gcc -ansi -Wall -std=c99 -o [prog_name] [prog_name.c]       **
*****************************************************************************/


#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <stdbool.h>
#include <string.h>


/*DEFINIÇÃO DOS TIPOS POSSIVEIS DO POOL DE CONSTANTES*/

#define UTF8 1
#define INTEGER 3
#define FLOAT 4
#define LONG 5
#define DOUBLE 6
#define CLASS 7
#define STRING 8
#define FIELD_REF 9
#define METHOD_REF 10
#define INTERFACE_REF 11
#define NAME_AND_TYPE 12


/*DEFINIÇÃO PARA TRATAMENTO DE POSSIVEIS ERROS*/

#define MISSING_ARGUMENT 1
#define CANT_OPEN 2
#define INVALID_FILE 3
#define UNKNOWN_TYPE 4

/*CONSTANTES PARA FORMATAÇÃO DOS DADOS*/

const char *type_Names [12] = {"UFT8_info", "-", "Integer", "Float", "Long", "Double", "Class_info", "String_info", "Fieldref_info", "Methodref_info", "Interface", "Name and Type"};
const char *flag_name [5] = {"ACC_PUBLIC", "ACC_FINAL", "ACC_SUPER", "ACC_INTERFACE", "ACC_ABSTRACT"};

/*struct de uniao para armazenar todos os tamanhos de variavel que
**serao lidos*/
typedef union {
	unsigned char *array; /*Ponteiro para uma strig*/
	unsigned char u1; /**/
	unsigned short u2;
	unsigned int u4;
}classLoadrType;

/*uma struct para armazenar*/
typedef struct {
	unsigned char tag;
	classLoadrType *info;
}cp_info;


/*Função lerU4: a partir do arquivo recebido, lê 4 bytes e inverte-os*/
unsigned int lerU4(FILE *fp){
	unsigned char aux;
	unsigned int ret = 0;

	for(int i = 0; i <= 3; i++){ /*lê os 4 primeiros bytes do .class*/
		fread(&aux, 1, 1, fp); 
		ret = ret << 8;
		ret = ret | aux;
	}
	/*printf("%08x\n", ret);*/

	return ret;
}

/*lerU2: a partir do arquivo recebido, lê 2 bytes e inverte-os*/
unsigned short lerU2 (FILE *fp){
	unsigned char aux;
	unsigned short ret = 0;

	fread(&aux, 1, 1, fp);
	fread(&aux, 1, 1, fp);

	ret <<= 8;
	ret |= aux;

	return ret;
}

/*lerU1: a partir do arquivo recebido, lê 1 byte do mesmo.*/
unsigned char lerU1 (FILE *fp){
	unsigned char ret;

	fread(&ret, 1, 1, fp);
	/*printf("%02x\n", ret);*/
	return ret;
}

/*função para ler os bytes da string UTF8*/
unsigned char * lerU2UTF8 (int size, FILE *fp){
	unsigned char *ret = (unsigned char *) malloc(sizeof(unsigned char) * size);

	for(int i = 0; i < size; i++)
		ret[i] = lerU1(fp);
	
	return ret;
}

/*loadInfConstPoos: carrega as informacoes de pool de constate para memoria*/
int loadInfConstPool (cp_info *constPool, int const_pool_cont, FILE *fp){
	int i;

	/*percorre verificando os tipos da tags e carregando na memoria
	**de acordo.*/
	for(i = 1; i < const_pool_cont; i++){
		/*Carrega a tag que define o tipo da informação em cp_info*/
		constPool[i].tag = lerU1(fp);

		/*verifica s o tipo lido é conhecido de acordo com a tabela no slide*/
		if((constPool[i].tag <= 0) && (constPool[i].tag >= 12) && (constPool[i].tag == 2))
			return i; /*encerra a execução se não for conhecido*/

		/*checagem do campo info e leitura dos parametros de acordo com o tipo da tag lida*/
		switch (constPool[i].tag){
			printf("constPool[i].tag = %c\n", constPool[i].tag);
			case UTF8:/*contem um campo u2 e um array de bayte u1 como info*/
				constPool[i].info = (classLoadrType *) malloc(sizeof(classLoadrType) * 2);
				constPool[i].info[0].u2 = lerU2(fp); /*número de bytes no array de bytes*/
				constPool[i].info[1].array = lerU2UTF8(constPool[i].info[0].u2, fp); /*bytes da string*/
				break;

			case INTEGER: /*possui apenas um campo u4 em info*/
			case FLOAT:
				constPool[i].info = (classLoadrType *) malloc(sizeof(classLoadrType));
				constPool[i].info[0].u4 = lerU4(fp);
				break;

			case LONG: /*possui dois campos u4 em info*/
			case DOUBLE:
				constPool[i].info = (classLoadrType *) malloc(sizeof(classLoadrType) * 2);
				constPool[i].info[0].u4 = lerU4(fp);
				constPool[i].info[1].u4 = lerU4(fp);
				break;

			case CLASS: /*contem um campo u2 em info*/
			case STRING:
				constPool[i].info = (classLoadrType *) malloc(sizeof(classLoadrType));
				constPool[i].info[0].u2 = lerU2(fp);
				break;

			case FIELD_REF: /*contem dois campos u2 em info*/
			case METHOD_REF:
			case INTERFACE_REF:
			case NAME_AND_TYPE:
				constPool[i].info = (classLoadrType *) malloc(sizeof(classLoadrType) * 2);
				constPool[i].info[0].u2 = lerU2(fp);
				constPool[i].info[1].u2 = lerU2(fp);
				break;
		}
	}
	/*retorna o numero de elementos lidos*/
	return i;
}


/*show_UTF8: monta e mostra a string UTF8*/
void show_UTF8 (int size, unsigned char * str){
	int i = 0;

	while(i < size){ /*enquanto tiver byte no array de bytes*/
		if(!(str[i] & 0x80)){ /*1 byte para utf-8: Se inverso é true, então caracter é representado por 0*/
			printf("%c\n", str[i]);
		}else{	/*Caso não esteja na faixa dos caracteres "usuais"*/
			unsigned short aux;
			if(!(str[i+1] & 0x20)){	/*para utf8 de 2 byte*/
				aux = ((str[i] & 0xf) << 6) + ((str[i+1] & 0x3f));
			}else{	/*para utf8 de 3 byte*/
				aux = ((str[i] & 0xf) << 12) + ((str[i+1] & 0x3f) << 6) + (str[i + 2] & 0x3f);
				i++;
			}
			i++;
			printf("%d\n", aux);
		}
	}
}


void showConstPool(int const_pool_cont, cp_info *constPool){

	printf("Pool de Constantes:\n");

	for(int i = 1; i < const_pool_cont; i++){
		printf("\t[%d] = %s\n", i, type_Names[constPool[i].tag-1]);

		switch(constPool[i].tag-1){
			case INTEGER: /*tem um campo u4 em info*/
				printf("%c", constPool[i].info[0].u4);
				break;

			case UTF8: /*tem um campo u2 e um array u1 como info*/
				show_UTF8(constPool[i].info[0].u2, constPool[i].info[1].array);
				break;

			case FLOAT:
				break;

			case LONG:
				break;

			case DOUBLE:
				break;

			case CLASS:
				break;

			case STRING:
				break;

			case INTERFACE_REF:
				
			case METHOD_REF:
			
			case FIELD_REF:
				break;

			case NAME_AND_TYPE:
				break;
		}
	}
	printf("\n");
}


int main (int argc, char *argv[]){

	/*Verifica se o arquivo foi passado*/
	if(argc != 2){
		printf("ERRO: deve ser passado um argumento!\n");
		printf("Execute com:[program_name] [arquivo.class]\n");
		return MISSING_ARGUMENT;
	}

	FILE *fp = fopen(argv[1], "rb");

	/*Verifica se o arquivo recebido foi aberto com sucesso*/
	if(fp == NULL){
		printf("ERRO: não foi possivel abrir o arquivo %s\n", argv[1]);
		return CANT_OPEN;
	}

	/*Verificação da assinatura do arquivo (verifica se esta presente cafe babe)*/
	if(lerU4(fp) != 0xcafebabe){
		printf("ERRO: Arquivo invalido.\nAssinatura \"cafe babe\" nao encontrado");
		return INVALID_FILE;
	}


	/*lê a minor version*/
	int minVersion = lerU2(fp);
	printf("\nminVersion = %d\n", minVersion);

	/*lê a major version*/
	int majVersion = lerU2(fp);
	printf("majVersion = %d\n", majVersion);

	/*lê quantidade de constates no pool de constate*/
	int const_pool_cont = lerU2(fp);
	printf("Constant pool count: %d\n\n", const_pool_cont);

	/*Ponteiro do tipo cp_info*/
	cp_info *constPool;

	/*aloca a memoria (tabela) do tamanho da quantidade de entrada no CP*/
	constPool = (cp_info *) malloc(sizeof(cp_info) * const_pool_cont);
	int checkCP = loadInfConstPool(constPool, const_pool_cont, fp);

	
	/*Verifica se todos os elementos da entrada do CP foram lidos*/
	if(const_pool_cont != checkCP){
		printf("ERRO: Tipo desconhecido para pool de constante.\n");
		printf("Nao foi possivel carregar todas as entradas do CP.\n");
		printf("Elementos #%d\n", checkCP+1);

		return UNKNOWN_TYPE;
	}
	
	/*Exibe algumas coisas da CP*/
	showConstPool(const_pool_cont, constPool);

	return 0;
}

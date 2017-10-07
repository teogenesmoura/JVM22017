
/****************************************************************************
** MEMBROS:                                                                **
**		Aluno 1: Jean Pierre Sissé                                         **
**		Aluno 2: Samuel Sousa Almeida                                      **
**		Aluno 3:                                                           **
**		Aluno 4:                                                           **
**		Aluno 5:                                                           **
**                                                                         **
** Descrição: Lietor de arquivo .class                                     **
**compile com: gcc -ansi -Wall -std=c99 -o [prog_name] [prog_name.c] -lm   **
*****************************************************************************/


#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <stdbool.h>
#include <string.h>
#include "leitor.h"

/*Função lerU4: a partir do arquivo recebido, lê 4 bytes e inverte-os*/
unsigned int lerU4(FILE *fp){
	unsigned char aux;
	unsigned int ret = 0;

	for(int i = 0; i <= 3; i++){ /*for para ler os 4 bytes do .class*/
		fread(&aux, 1, 1, fp); 	/*lê um byte*/
		ret = ret << 8;			/*Deslocamento de 8 bits a esquerda*/
		ret = ret | aux;		/*Faz um or bit a bit*/
	}
	/*printf("%08x\n", ret);*/

	return ret;
}

/*lerU2: a partir do arquivo recebido, lê 2 bytes e inverte-os*/
unsigned short lerU2 (FILE *fp){
	unsigned char aux;
	unsigned short ret = 0;

	fread(&ret, 1, 1, fp);
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

/* função para ler os bytes da string UTF8.
** aloca a memória para a quantidade de byte no array de byte.
** faz um loop com a qtd de byte no array lendo byte a byte e armazenando 
** na memoria alocada.*/
unsigned char * ler_UTF8 (int size, FILE *fp){
	unsigned char *ret = (unsigned char *) malloc(sizeof(unsigned char) * size);

	for(int i = 0; i < size; i++)
		ret[i] = lerU1(fp);
	
	return ret;
}

/*Retirado do slide do prof, efetua conversão do valor para float.*/
float convert_u4_toFloat(classLoadrType ent){
	float out;

	int s = ((ent.u4 >> 31) == 0) ? 1 : -1;
	int e = ((ent.u4 >> 23) & 0xff);
	int m = (e == 0) ? (ent.u4 & 0x7fffff) << 1 : (ent.u4 & 0x7fffff) | 0x800000;

	out = s * m * (pow(2,(e-150)));

	return out;
}

/*Converte o valor em u4 para long.*/
long convert_u4_toLong (classLoadrType entLow, classLoadrType entHigh){
	long out;

	return	out = (((long)entHigh.u4) << 32) | entLow.u4;
}

/*Converte o valor em u4 para double.*/
double convert_u4_toDouble(classLoadrType entLow, classLoadrType entHigh){
	double out;

	int s = ((convert_u4_toLong(entLow, entHigh) >> 63) == 0) ? 1 : -1;
	int e = ((convert_u4_toLong(entLow, entHigh) >> 52) & 0x7ffL);
	long m = (e == 0) ? (convert_u4_toLong(entLow, entHigh) & 0xfffffffffffffL) << 1 : (convert_u4_toLong(entLow, entHigh) & 0xfffffffffffffL) | 0x10000000000000L;

	return out = s * m * (pow(2,(e-1075)));
}

/*show_UTF8: monta e mostra a string UTF8*/
void show_UTF8 (int size, unsigned char * str){
	int i = 0;

	/*printf("   ");*/
	while(i < size){ 	/*enquanto tiver byte no array de bytes*/
		if(!(str[i] & 0x80)){ 	/*1 byte para utf-8: Se inverso é true, então caracter é representado por 0, ou seja, o bit 7 é 0*/
			printf("%c", str[i]);
		}else{	/*Caso não esteja na faixa dos caracteres "usuais"*/
			unsigned short aux;
			if(!(str[i+1] & 0x20)){	/* para utf8 de 2 bytes */
				aux = ((str[i] & 0xf) << 6) + ((str[i+1] & 0x3f));
			}else{	/*para utf8 de 3 byte*/
				aux = ((str[i] & 0xf) << 12) + ((str[i+1] & 0x3f) << 6) + (str[i + 2] & 0x3f);
				i++;
			}
			i++;
			printf("%d", aux);
		}
		i++;
	}
}


/* função recursiva para desreferenciar indices das constantes
** que contem strings nas suas informações.
** Recebe o indice (posição) de uma constante na tabela
** e o penteiro para a tabela e recursivamente acessa os
** indices na tabela até chegar no indice referenciando
** estrutura UTF8 que contem a string da constante inicialmente
** passado.*/
void dereference_index_UTF8 (int index, cp_info *cp){ 
	switch(cp[index].tag){
		case UTF8: /*Neste caso, estamos no caso trivial, onde a estrutura contem a string desejada.*/
			show_UTF8(cp[index].info[0].u2, cp[index].info[1].array); /*eh passado qtd de byte no array de byte e array contendo bytes*/
			break;

		case CLASS:
		case STRING:
			dereference_index_UTF8(cp[index].info[0].u2, cp);
			break;

		case INTERFACE_REF:
		case METHOD_REF:
		case FIELD_REF:
			dereference_index_UTF8(cp[index].info[0].u2, cp);
			printf("|");
			dereference_index_UTF8(cp[index].info[1].u2, cp);
			break;

		case NAME_AND_TYPE:
			dereference_index_UTF8(cp[index].info[0].u2, cp);
			printf(":");
			dereference_index_UTF8(cp[index].info[1].u2, cp);
			break;
	}
}

/*A recebe a qtd de constantes presentes na tabela do CP
** e ponteiro para a tabela dos constantes.
** Percorre a tabela e exibe toda a informação contida nela.
** %d|%d mostra os indices na estrutura seguido das informações
** relacionadas aos strings nas outras estruturas.*/
void showConstPool(int const_pool_cont, cp_info *constPool){

	printf("Pool de Constantes:\n");

	for(int i = 1; i < const_pool_cont; i++){
		printf("\t[%d] = %s", i, type_Names[constPool[i].tag-1]);

		switch(constPool[i].tag){
			case UTF8: /*tem um campo u2 e um array u1 como info*/
				printf("\t\t");
				show_UTF8(constPool[i].info[0].u2, constPool[i].info[1].array);
				break;
			
			case FLOAT:
				printf("%f", convert_u4_toFloat(constPool[i].info[0]));
				break;

			case INTEGER:
				printf("%d", constPool[i].info[0].u4);
				break;

			case LONG:
				printf("%ld", convert_u4_toLong(constPool[i].info[0], constPool[i].info[1]));
				break;
			
			case DOUBLE:
				printf("%lf", convert_u4_toDouble(constPool[i].info[0], constPool[i].info[1]));
				break;
			case CLASS:
			case STRING:
				printf("   #%d\t\t", constPool[i].info[0].u2);
				dereference_index_UTF8 (i, constPool);
				break;

			case INTERFACE_REF:
			case FIELD_REF:
			case METHOD_REF:
				printf("  %d|%d\t", constPool[i].info[0].u2, constPool[i].info[1].u2);
				dereference_index_UTF8(i, constPool);
				break;

			case NAME_AND_TYPE:
				printf("  %d|%d\t",  constPool[i].info[0].u2, constPool[i].info[1].u2);
				dereference_index_UTF8(i, constPool);
				break;
		}
		printf("\n");
	}
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

			case UTF8:/*contem um campo u2 e um array de bayte u1 como info*/
				constPool[i].info = (classLoadrType *) malloc(sizeof(classLoadrType) * 2);
				constPool[i].info[0].u2 = lerU2(fp); /*lê o número de bytes que o array de bytes contem*/
				constPool[i].info[1].array = ler_UTF8(constPool[i].info[0].u2, fp); /*bytes da string*/
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

void loadInterfaces(){}
void loadFields(){}
void loadMethods(){}
int main (int argc, char *argv[]){
	uint32_t magicnumber;
	uint16_t minVersion, majVersion, const_pool_cont;
	cp_info *constPool;	/*Ponteiro do tipo cp_info*/

	uint16_t access_flags, this_class, super_class;
	uint16_t interfaces_count, fields_count, methods_count, attributes_count;
	uint16_t *interfaces;
	/* Fields, Methods and Attributes precisam dos proprios tipos de dados para o array */
	int checkCP;

	/*Verifica se o arquivo foi passado*/
	/*
	if(argc != 2){
		printf("ERRO: deve ser passado um argumento!\n");
		printf("Execute com:[program_name] [arquivo.class]\n");
		return MISSING_ARGUMENT;
	}

	FILE *fp = fopen(argv[1], "rb");
	*/
	/*Verifica se o arquivo recebido foi aberto com sucesso*/
	/*
	if(fp == NULL){
		printf("ERRO: não foi possivel abrir o arquivo %s\n", argv[1]);
		return CANT_OPEN;
	}
	*/
	/*Verificação da assinatura do arquivo (verifica se esta presente cafe babe)*/
	/*
	if(lerU4(fp) != 0xcafebabe){
		printf("ERRO: Arquivo invalido.\nAssinatura \"cafe babe\" nao encontrado");
		return INVALID_FILE;
	}
	*/

	FILE *fp = fopen("hello.class", "rb");

	magicnumber = lerU4(fp);
	/*lê a minor version*/
	minVersion = lerU2(fp);
	printf("\nminVersion = 0x%x\n", minVersion);

	/*lê a major version*/
	majVersion = lerU2(fp);
	printf("majVersion = 0x%x\n", majVersion);

	/*lê quantidade de constates no pool de constate*/
	const_pool_cont = lerU2(fp);
	printf("Constant pool count: %d\n\n", const_pool_cont);


	/*aloca a memoria (tabela) do tamanho da quantidade de const na entrada no CP*/
	constPool = (cp_info *) malloc(sizeof(cp_info) * const_pool_cont);
	checkCP = loadInfConstPool(constPool, const_pool_cont, fp);

	/*Verifica se todos os elementos da entrada do CP foram lidos*/
	if(const_pool_cont != checkCP){
		printf("ERRO: Tipo desconhecido para pool de constante.\n");
		printf("Nao foi possivel carregar todas as entradas do CP.\n");
		printf("Elementos #%d\n", checkCP+1);
		return UNKNOWN_TYPE;
	}

	/*Chamada para mostrar CP*/
	showConstPool(const_pool_cont, constPool);
	/* Partindo agora para a leitura do restante dos elementos do .class */
	/* access_flags, this_class, super_class, interfaces_count */
	access_flags = lerU2(fp);
	this_class = lerU2(fp);
	super_class = lerU2(fp);
	interfaces_count = lerU2(fp);
	printf (" access_flags: 0x%04x \n this_class: 0x%04x \n super_class: 0x%04x \n", access_flags, this_class, super_class, interfaces_count);

	interfaces = (uint16_t*) (malloc (sizeof(uint16_t)*interfaces_count));
	loadInterfaces();	/* Funcao vazia por enquanto. */

	fields_count = lerU2(fp);
	loadFields();		/* Funcao vazia por enquanto. */

	methods_count = lerU2(fp);
	loadMethods(fp, methods_count);		/* Funcao em implementacao. */

	printf (" interfaces_count: 0x%04x \n fields_count: 0x%04x \n methods_count: 0x%04x \n", interfaces_count, fields_count, methods_count);

	return 0;
}

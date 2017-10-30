
/****************************************************************************
** MEMBROS:                                                                **
**		Aluno 1: Jean Pierre Sissé                                         **
**		Aluno 2: Samuel Sousa Almeida                                      **
**		Aluno 3: Rafael Rodrigues                                          **
**		Aluno 3: Raphael Rodrigues                                         **
**		Aluno 4: Teogenes Moura                                            **
**		Aluno 5: Michel Melo                                               **
**                                                                         **
** Descrição: Lietor de arquivo .class                                     **
**compile com: gcc -ansi -Wall -std=c99 -o [prog_name] [prog_name.c] -lm   **
*****************************************************************************/

#define LEITOR_SERVER

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <stdbool.h>
#include <string.h>
#include "leitor.h"
#include "exibidor.h"
#include <stdint.h>

/*Função ler_u4: a partir do arquivo recebido, lê 4 bytes e inverte-os*/
uint32_t ler_u4(FILE *fp){
	uint8_t aux;
	uint32_t ret = 0;

	for(int i = 0; i <= 3; i++){ /*for para ler os 4 bytes do .class*/
		fread(&aux, 1, 1, fp); 	/*lê um byte*/
		ret = ret << 8;			/*Deslocamento de 8 bits a esquerda*/
		ret = ret | aux;		/*Faz um or bit a bit*/
	}

	return ret;
}

/*ler_u2: a partir do arquivo recebido, lê 2 bytes e inverte-os*/
uint16_t ler_u2 (FILE *fp){
	uint8_t aux;
	uint16_t ret = 0;

	fread(&ret, 1, 1, fp);
	fread(&aux, 1, 1, fp);

	ret <<= 8;
	ret |= aux;

	return ret;
}

/*ler_u1: a partir do arquivo recebido, lê 1 byte do mesmo.*/
uint8_t ler_u1 (FILE *fp){
	uint8_t ret;

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
		ret[i] = ler_u1(fp);
	
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
long convert_u4_toLong (classLoadrType entHigh, classLoadrType entLow){
	long out;

	out = (((long) entHigh.u4) << 32) | entLow.u4;
	return out;
}

/*Converte o valor em u4 para double.*/
double convert_u4_toDouble(classLoadrType entHigh, classLoadrType entLow){
	double out;

	long check_boundaries = convert_u4_toLong(entHigh, entLow);

	if(check_boundaries == 0x7ff0000000000000L){
		/*verifica se retorna +infinito*/
	}else if(check_boundaries == 0xfff0000000000000L){
		/*verifica se retorna -infinito*/
	}else if((check_boundaries >= 0x7ff0000000000001L) && (check_boundaries <= 0x7ffffffffffffL)){
		/*verifica se retorna NaN*/
	}else if((check_boundaries >= 0xfff0000000000001L) && (check_boundaries <= 0xffffffffffffffffL)){
		/*verifica se retorna NaN*/
	}else{
		int s = ((check_boundaries >> 63) == 0) ? 1 : -1;
		int e = ((check_boundaries >> 52) & 0x7ffL);
		long m = (e == 0) ? (check_boundaries & 0xfffffffffffffL) << 1 : (check_boundaries & 0xfffffffffffffL) | 0x10000000000000L;
		out = s * m * (pow(2,(e-1075)));
	}

	return out;
}

/*loadInfConstPoos: carrega as informacoes de pool de constate para memoria*/
int loadInfConstPool (cp_info *constPool, int const_pool_cont, FILE *fp){
	int i;

	/*percorre verificando os tipos da tags e carregando na memoria
	**de acordo.*/
	for(i = 1; i < const_pool_cont; i++){
		/*Carrega a tag que define o tipo da informação em cp_info*/
		constPool[i].tag = ler_u1(fp);

		/*verifica s o tipo lido é conhecido de acordo com a tabela no slide*/
		if((constPool[i].tag <= 0) && (constPool[i].tag >= 12) && (constPool[i].tag == 2))
			return i; /*encerra a execução se não for conhecido*/

		/*checagem do campo info e leitura dos parametros de acordo com o tipo da tag lida*/
		switch (constPool[i].tag){

			case UTF8:/*contem um campo u2 e um array de bayte u1 como info*/
				constPool[i].info = (classLoadrType *) malloc(sizeof(classLoadrType) * 2);
				constPool[i].info[0].u2 = ler_u2(fp); /*lê o número de bytes que o array de bytes contem*/
				constPool[i].info[1].array = ler_UTF8(constPool[i].info[0].u2, fp); /*bytes da string*/
				break;

			case INTEGER: /*possui apenas um campo u4 em info*/
			case FLOAT:
				constPool[i].info = (classLoadrType *) malloc(sizeof(classLoadrType));
				constPool[i].info[0].u4 = ler_u4(fp);
				break;

			case LONG: /*possui dois campos u4 em info*/
			case DOUBLE:
				constPool[i].info = (classLoadrType *) malloc(sizeof(classLoadrType) * 2);
				constPool[i].info[0].u4 = ler_u4(fp);
				constPool[i].info[1].u4 = ler_u4(fp);
				break;

			case CLASS: /*contem um campo u2 em info*/
			case STRING:
				constPool[i].info = (classLoadrType *) malloc(sizeof(classLoadrType));
				constPool[i].info[0].u2 = ler_u2(fp);
				break;

			case FIELD_REF: /*contem dois campos u2 em info*/
			case METHOD_REF:
			case INTERFACE_REF:
			case NAME_AND_TYPE:
				constPool[i].info = (classLoadrType *) malloc(sizeof(classLoadrType) * 2);
				constPool[i].info[0].u2 = ler_u2(fp);
				constPool[i].info[1].u2 = ler_u2(fp);
				break;
		}
	}
	/*retorna o numero de elementos lidos*/
	return i;
}

/*lê um atributo*/
attribute_info ler_attribute(FILE *fp){
	attribute_info out;

	out.attribute_name_index = ler_u2(fp);
	out.attribute_length = ler_u4(fp);
	out.info = (unsigned char *) malloc(sizeof(unsigned char) * out.attribute_length);
	for (int i = 0; i < out.attribute_length; i++)
	out.info = (uint8_t *) malloc(sizeof(uint8_t) * out.attribute_length);
	for (int i = 0; i < out.attribute_length; ++i)
		out.info[i] = ler_u1(fp);
	
	return out;
}

/*Lê os fields*/
field_info ler_fields (FILE *fp){
	field_info out;

	out.access_flags = ler_u2(fp) & 0x0df;
	out.name_index = ler_u2(fp);
	out.descriptor_index = ler_u2(fp);
	out.attribute_count = ler_u2(fp);
	out.attributes = (attribute_info *) malloc(sizeof(attribute_info) * out.attribute_count);
	for(int i = 0; i < out.attribute_count; i++)
		out.attributes[i] = ler_attribute(fp);

	return out;
}


/* Funcoes de methods */
method_info ler_methods(FILE *fp){
	method_info out;
	out.access_flags = ler_u2(fp);
	out.name_index = ler_u2(fp);
	out.descriptor_index = ler_u2(fp);
	out.attributes_count = ler_u2(fp);
	out.attributes = (attribute_info *) malloc(sizeof(attribute_info) * out.attributes_count);
	for (int i=0;i<out.attributes_count;i++)
		out.attributes[i] = ler_attribute(fp);
	return out;
}


/*carrega e mostra todas interfaces que estão presentes.*/
void loadInterfaces(uint16_t *interfaces, int interfaces_count, cp_info *constPool, FILE *fp){

	/*printf("	Interface count: %d\n", interfaces_count);*/
	for (int i = 0; i < interfaces_count; ++i){
		interfaces[i] = ler_u2(fp);
		/*
		printf("\tInterface %d:", i);
		dereference_index_UTF8(interfaces[i], constPool);
		printf("\n");
		*/
	}
}

int init_leitor(FILE *fp){
	attribute_info *attributes;

	cFile classFile;
	int checkCP;

	/*vetor booleano para controle de flags presentes.*/
	bool splitFlags[5];


	/*Verificação da assinatura do arquivo (verifica se esta presente cafe babe)*/
	if((classFile.magic = ler_u4(fp)) != 0xcafebabe){
		printf("ERRO: Arquivo invalido.\nAssinatura \"cafe babe\" nao encontrado");
		return INVALID_FILE;
	}

	classFile.minor_version = ler_u2(fp);		/* lê a minor version */
	classFile.major_version = ler_u2(fp);		/* lê a major version */
	classFile.constant_pool_count = ler_u2(fp);	/* lê quantidade de constates no pool de constantes */
	/* aloca a memoria (tabela) do tamanho da quantidade de const na entrada no CP */
	classFile.constant_pool = (cp_info *) malloc(sizeof(cp_info) * classFile.constant_pool_count);
	checkCP = loadInfConstPool(classFile.constant_pool, classFile.constant_pool_count, fp);



	/*Verifica se todos os elementos da entrada do CP foram lidos*/
	if(classFile.constant_pool_count != checkCP){
		printf("ERRO: Tipo desconhecido para pool de constante.\n");
		printf("Nao foi possivel carregar todas as entradas do CP.\n");
		printf("Elementos #%d\n", checkCP+1);
		return UNKNOWN_TYPE;
	}
	
	/* access_flags, this_class, super_class, interfaces_count */
	classFile.access_flags = ler_u2(fp);
	
	/*Assumindo que todas as flags são false (ou seja, não estão presentes)*/
	for(int i = 0; i < 5; i++){
		splitFlags[i] = false;
	}

	/*Testa uma a uma setando como true as que estão presentes*/
	if (classFile.access_flags & 0x01){
		splitFlags[0] = true;
	}
	if (classFile.access_flags & 0x010){
		splitFlags[1] = true;
	}
	if (classFile.access_flags & 0x020){
		splitFlags[2] = true;
	}
	if (classFile.access_flags & 0x0200){
		splitFlags[3] = true;
	}
	if (classFile.access_flags & 0x0400){
		splitFlags[4] = true;
	}

	classFile.this_class = ler_u2(fp);
	classFile.super_class = ler_u2(fp);
	classFile.interfaces_count = ler_u2(fp);
	classFile.interfaces = (uint16_t*) (malloc (sizeof(uint16_t)*classFile.interfaces_count));
	/*Carregando e mostrando todas as interfaces que estão presentes*/
	loadInterfaces(classFile.interfaces, classFile.interfaces_count, classFile.constant_pool, fp);

	classFile.fields_count = ler_u2(fp);
	classFile.fields = (field_info *) malloc(sizeof(field_info) * classFile.fields_count);
	/*Carrega e mostra os fields existentes */

	for (int i = 0; i < classFile.fields_count; ++i){
		classFile.fields[i] = ler_fields(fp);
		/*show_fields(classFile.constant_pool, classFile.fields[i]);*/

	}

	classFile.methods_count = ler_u2(fp);
	classFile.methods = (method_info*) malloc (sizeof(method_info)*classFile.methods_count);

	for (int i = 0;i < classFile.methods_count; i++){
		/* printf ("\n	Method [%d]\n", i); */
		classFile.methods[i] = ler_methods(fp);
		/* show_methods(classFile.constant_pool, classFile.methods[i]);*/
	}

	int attributes_count = ler_u2(fp);
	printf("attribute_count = %d\n", attributes_count);
	attributes = (attribute_info *) malloc (sizeof(attribute_info) * attributes_count);
	for (int i = 0; i < attributes_count; i++){
		attributes[i] = ler_attribute(fp);
		/*printf("%x\n", attributes[i]);*/
	}

	/*Mostra as informações basicas como magic number, minversion...etc*/
	infoBasic(classFile);
	/*chama a função para mostrar as flags ativas*/
	//show_flags(classFile.access_flags, splitFlags);
	/*Exibe a informação (string) da classe*/
	//dereference_index_UTF8(classFile.this_class, classFile.constant_pool);
	/*Exibe a informação (string) da super_classe*/
	//dereference_index_UTF8(classFile.super_class, classFile.constant_pool);
	//showConstPool(classFile.constant_pool_count, classFile.constant_pool);

	return 0;
}

int findMain (cFile classFile){
	int i;

	while (i<classFile.methods_count){
		if (strcmp(classFile.constant_pool[(classFile.methods[i].name_index)].info[1].array, "main")==0){
			return i;
		}
		i++;
	}
	return -1;
}
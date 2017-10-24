
/****************************************************************************
** MEMBROS:                                                                **
**		Aluno 1: Jean Pierre Sissé                                         **
**		Aluno 2: Samuel Sousa Almeida                                      **
**		Aluno 3: Raphael Rodrigues                                         **
**		Aluno 4: Teogenes Moura                                            **
**		Aluno 5: Michel Melo                                               **
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
	/*printf("%08x\n", ret);*/

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

/*show_UTF8: monta e mostra a string UTF8*/
void show_UTF8 (int size, unsigned char * str){
	int i = 0;

	/*printf("   ");*/
	while(i < size){ 	/*enquanto tiver byte no array de bytes*/
		if(!(str[i] & 0x80)){ 	/*1 byte para utf-8: Se inverso é true, então caracter é representado por 0, ou seja, o bit 7 é 0*/
			printf("%c", str[i]);
		}else{	/*Caso não esteja na faixa dos caracteres "usuais"*/
			uint16_t aux;
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

/* A recebe a qtd de constantes presentes na tabela do CP
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
				printf("\t%f", convert_u4_toFloat(constPool[i].info[0]));
				break;

			case INTEGER:
				printf("\t%d", constPool[i].info[0].u4);
				break;

			case LONG:
				printf("\t%ld", convert_u4_toLong(constPool[i].info[0], constPool[i].info[1]));
				break;
			
			case DOUBLE:
				printf("\t%lf", convert_u4_toDouble(constPool[i].info[0], constPool[i].info[1]));
				break;
			case CLASS:
			case STRING:
				printf("   #%d\t\t", constPool[i].info[0].u2);
				dereference_index_UTF8 (i, constPool);
				break;

			case INTERFACE_REF:
			case FIELD_REF:
			case METHOD_REF:
				printf("  #%d|#%d\t", constPool[i].info[0].u2, constPool[i].info[1].u2);
				dereference_index_UTF8(i, constPool);
				break;

			case NAME_AND_TYPE:
				printf("  #%d|#%d\t",  constPool[i].info[0].u2, constPool[i].info[1].u2);
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

/*Verifica flags ativas e mostra.*/
void show_flags(uint16_t access_flags, bool *flags){
	bool first = true; /*Apenas para exibir a mensagem "Flags" uma vez na tela.*/

	for (int i = 0; i < 5; ++i){
		if(flags[i]){
			if(first){
				printf("	ACcess flags: 0x%04x", access_flags);
			}else{
				printf("]");
			}
			first = false;
			printf("[%s", flag_name[i]);
		}
	}
	printf("]\n");
}

/*lê um atributo*/
attribute_info ler_attribute(FILE *fp){
	attribute_info out;

	out.attribute_name_index = ler_u2(fp);
	out.attribute_length = ler_u4(fp);
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

/*mostra as flags do campo verificando todas as flags presentes no field*/
void show_field_flags(uint16_t flags){
	bool first = true;

	if(flags & 0x01){
		if(first){
			printf(" Flags: ");
			first = false;
		}else{
			printf(", ");
		}
		printf("[ACC_PUBLIC]");
	}

	if(flags & 0x02){
		if(first){
			printf(" Flags: ");
			first = false;
		}else{
			printf(", ");
		}
		printf("[ACC_PRIVATE]");
	}

	if(flags & 0x04){
		if(first){
			printf(" Flags: ");
			first = false;
		}else{
			printf(", ");
		}
		printf("[ACC_PROTECTED]");
	}

	if(flags & 0x08){
		if(first){
			printf(" Flags: ");
			first = false;
		}else{
			printf(", ");
		}
		printf("[ACC_STATIC]");
	}

	if(flags & 0x010){
		if(first){
			printf(" Flags: ");
			first = false;
		}else{
			printf(", ");
		}
		printf("[ACC_FINAL]");
	}

	if(flags & 0x0040){
		if(first){
			printf(" Flags: ");
			first = false;
		}else{
			printf(", ");
		}
		printf("[ACC_VOLATILE]");
	}

	if(flags & 0x0080){
		if(first){
			printf(" Flags: ");
			first = false;
		}else{
			printf(", ");
		}
		printf("[ACC_TRANSIENT]");
	}

	if(flags & 0x1000){
		if(first){
			printf(" Flags: ");
			first = false;
		}else{
			printf(", ");
		}
		printf("[ACC_SYNTHETIC]");
	}

	if(flags & 0x4000){
		if(first){
			printf(" Flags: ");
			first = false;
		}else{
			printf(", ");
		}
		printf("[ACC_ENUM]");
	}

	printf("\n");
}

/*carrega e mostra todas interfaces que estão presentes.*/
void loadInterfaces(uint16_t *interfaces, int interfaces_count, cp_info *constPool, FILE *fp){

	printf("	Interface count: %d\n", interfaces_count);
	for (int i = 0; i < interfaces_count; ++i){
		interfaces[i] = ler_u2(fp);
		printf("\tInterface %d:", i);
		dereference_index_UTF8(interfaces[i], constPool);
		printf("\n");
	}
}


void show_field_attribute(cp_info *cp, attribute_info attribute){
	printf(" Nome do atributo: ");
	dereference_index_UTF8(attribute.attribute_name_index, cp);

	printf("\t");
	printf(" Tamanho: %d", attribute.attribute_length);

	/*Completar a função para diferente tipos de atributo*/
}

/*Mostra um field*/
void show_fields (cp_info *cp, field_info fields){
	/*mostra flags*/
	show_field_flags(fields.access_flags);

	printf(" Nome do campo: ");
	dereference_index_UTF8(fields.name_index, cp);
	printf("\n");

	printf(" Descriptor do campo: ");
	dereference_index_UTF8(fields.descriptor_index, cp);
	printf("\n");

	printf(" Numero de atributos: %d\n", fields.attribute_count);
	for (int i = 0; i < fields.attribute_count; ++i){
		printf(" Atributo[%d]: ", i);
		show_field_attribute(cp, fields.attributes[i]);
	}
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

void show_method_flags(uint16_t flags){
	/*bool first = true;*/

	if(flags & 0x0001){
		printf("[ACC_PUBLIC] \t");
	}
	if(flags & 0x0002){
		printf("[ACC_PRIVATE]\t");
	}
	if(flags & 0x0004){
		printf("[ACC_PROTECTED]\t");
	}
	if(flags & 0x0008){
		printf("[ACC_STATIC] \t");
	}
	if(flags & 0x0010){
		printf("[ACC_FINAL] \t");
	}
	if(flags & 0x0020){
		printf("[ACC_SYNCHRONIZED] \t");
	}
	if(flags & 0x0040){
		printf("[ACC_BRIDGE] \t");
	}
	if(flags & 0x0080){
		printf("[ACC_VARARGS] \t");
	}
	if(flags & 0x0100){
		printf("[ACC_NATIVE] \t");
	}
	if(flags & 0x0400){
		printf("[ACC_ABSTRACT] \t");
	}
	if(flags & 0x0800){
		printf("[ACC_STRICT] \t");
	}
	if(flags & 0x1000){
		printf("[ACC_SYNTHETIC] \t");
	}
}

void show_methods(cp_info *cp, method_info method){

	printf ("	access_flags: 0x%04x", method.access_flags);
	show_method_flags(method.access_flags);
	printf ("\n");
	printf ("	Name_index: ");
	dereference_index_UTF8(method.name_index, cp);
	printf ("\n");
	printf ("	Descriptor_index: ");
	dereference_index_UTF8(method.descriptor_index, cp);
	printf ("\n");
	printf ("	attribute_count: %d", method.attributes_count);
	printf ("\n");
	for (int i = 0; i < method.attributes_count; ++i){
		printf("\tAtributo [%d]: ", i);
		show_field_attribute(cp, method.attributes[i]);
		printf("\n");
	}
}

int main (int argc, char *argv[]){
	cFile classFile;
	
	method_info *methods;

	int checkCP;

	/*vetor booleano para controle de flags presentes.*/
	bool splitFlags[5];

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

	if((classFile.magic = ler_u4(fp)) != 0xcafebabe){
		printf("ERRO: Arquivo invalido.\nAssinatura \"cafe babe\" nao encontrado");
		return INVALID_FILE;
	}

	/*FILE *fp = fopen("hello.class", "rb");*/

	printf("Informações gerais:\n\n");

	printf ("	Magic number: 0x%x\n", classFile.magic);

	/*lê a minor version*/
	classFile.minor_version = ler_u2(fp);
	printf("	MinVersion = %d\n", classFile.minor_version);

	/*lê a major version*/
	classFile.major_version = ler_u2(fp);
	printf("	MajVersion = %d\n", classFile.major_version);

	/*lê quantidade de constates no pool de constate*/

	classFile.constant_pool_count = ler_u2(fp);
	printf("	Constant pool count: %d\n", classFile.constant_pool_count);


	/*aloca a memoria (tabela) do tamanho da quantidade de const na entrada no CP*/

	classFile.constant_pool = (cp_info *) malloc(sizeof(cp_info) * classFile.constant_pool_count);
	checkCP = loadInfConstPool(classFile.constant_pool, classFile.constant_pool_count, fp);

	/*Verifica se todos os elementos da entrada do CP foram lidos*/
	if(classFile.constant_pool_count != checkCP){
		printf("ERRO: Tipo desconhecido para pool de constante.\n");
		printf("Nao foi possivel carregar todas as entradas do CP.\n");
		printf("Elementos #%d\n", checkCP+1);
		return UNKNOWN_TYPE;
	}
	
	/* Partindo agora para a leitura do restante dos elementos do .class */
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

	/*chama a função para mostrar as flags ativas*/
	show_flags(classFile.access_flags, splitFlags);

	classFile.this_class = ler_u2(fp);
	printf("	this_class_info: ");
	/*Exibe a informação (string) da classe*/
	dereference_index_UTF8(classFile.this_class, classFile.constant_pool);
	printf("\n");

	classFile.super_class = ler_u2(fp);
	printf("	super_class_info: ");
	/*Exibe a informação (string) da super_classe*/
	dereference_index_UTF8(classFile.super_class, classFile.constant_pool);
	printf("\n");

	classFile.interfaces_count = ler_u2(fp);

	classFile.interfaces = (uint16_t*) (malloc (sizeof(uint16_t)*classFile.interfaces_count));
	/*Carregando e mostrando todas as interfaces que estão presentes*/
	loadInterfaces(classFile.interfaces, classFile.interfaces_count, classFile.constant_pool, fp);

	classFile.fields_count = ler_u2(fp);
	printf("	Field count: %d\n", classFile.fields_count);

	classFile.fields = (field_info *) malloc(sizeof(field_info) * classFile.fields_count);
	/*Carrega e mostra os fields existentes */
	for (int i = 0; i < classFile.fields_count; ++i){
		classFile.fields[i] = ler_fields(fp);
		show_fields(classFile.constant_pool, classFile.fields[i]);
	}

	classFile.methods_count = ler_u2(fp);
	printf("	Method count: %d\n\n", classFile.methods_count);

	/*################################################################*/
	/*Chamada para mostrar CP*/
	showConstPool(classFile.constant_pool_count, classFile.constant_pool);
	/*################################################################*/

	classFile.methods = (method_info*) malloc (sizeof(method_info)*classFile.methods_count);

	for (int i=0;i<classFile.methods_count;i++){
		printf ("\n	Method [%d]\n", i);
		classFile.methods[i] = ler_methods(fp);
		show_methods(classFile.constant_pool, classFile.methods[i]);
	}

	fclose(fp);
	printf("\n\n");
	return 0;
}







/* encontrar e carregar na array de classes object.class, classe presente no 
** pacote java.lang. Todas as classes em java diretamente ou indiretamente
** derivam de class object, portanto é necessário carregá-la no array de classes
** antes de carregar o .class passado pela linha de comando.
** class object implementa metodos que provê algumas funcionalidades
** nas outras classes java. */

#include "../headers/carregador.h"
#include "../headers/leitor.h"
#include "../headers/exibidor.h" // So pra debug, pode tirar depois.

void showObjectClass(){
	printf ("Magic number: 0x%x\n", classObject.magic);
	printf("MinVersion = %d\n", classObject.minor_version);
	printf("MajVersion = %d\n", classObject.major_version);
	printf("Constant pool count: %d\n", classObject.constant_pool_count);
	showConstPool(classObject.constant_pool_count, classObject.constant_pool);

	printf("Access flags: %s \n", show_cFile_flags(classObject));
	printf("This class: cp_info[%d] ", classObject.this_class);
	printf ("<");
	dereference_index_UTF8(classObject.this_class, classObject.constant_pool);
	printf (">\n");

	printf("Super class: cp_info[%d]", classObject.super_class);
	printf ("<");
	dereference_index_UTF8(classObject.super_class, classObject.constant_pool);
	printf (">\n");

	printf("Interfaces count: %d\n", classObject.interfaces_count);
	printf("Fields count: %d\n", classObject.fields_count);
	printf("Methods count: %d\n", classObject.methods_count);
}

void loadObjectMethods(cFile classObject, FILE *fp){
	int i, j, k;
	uint16_t name_index;
	char name[100];
	for (i=0;i<classObject.methods_count;i++){
		classObject.methods[i].access_flags = ler_u2(fp);
		classObject.methods[i].name_index = ler_u2(fp);
		classObject.methods[i].descriptor_index = ler_u2(fp);
		classObject.methods[i].attributes_count = ler_u2(fp);
		
		for (j=0;j<classObject.methods[i].attributes_count;j++){
			name_index = ler_u2(fp);
			sprintf (name, "%s", (char*)classObject.constant_pool[name_index].info[1].array);
			if (strcmp(name, "Code") == 0){
				classObject.methods[i].att_code = (AT_Code*) malloc (sizeof(AT_Code));
				classObject.methods[i].att_code->attribute_name_index = name_index;
				classObject.methods[i].att_code->attribute_length = ler_u4(fp);
				classObject.methods[i].att_code->max_stack = ler_u2(fp);
				classObject.methods[i].att_code->max_locals = ler_u2(fp);
				classObject.methods[i].att_code->code_length = ler_u4(fp);
				classObject.methods[i].att_code->code = (uint8_t*) malloc (sizeof(uint8_t)*(classObject.methods[i].att_code->code_length));
		
				for (k=0;k<classObject.methods[i].att_code->code_length;k++){
					printf ("Moving checkpoint\n");
					printf ("Code: %d", ler_u1(fp));
					//classObject.methods[i].att_code->code[k] = ler_u1(fp);
					//printf ("[%d] ", classObject.methods[i].att_code->code[k]);
				}
				

				// Atributo eh um code.
			}else if (strcmp((char*)classObject.constant_pool[name_index].info[1].array, "Exception") == 0){
				// Atributo eh uma exception
			}
			
		}
	}
}

void java_lang_object(){
	FILE *fp = fopen("../classfile/Object.class", "rb");
	if(fp == NULL){
		printf ("Erro abrindo Object.class");
		exit(0);
	}

	if((classObject.magic = ler_u4(fp)) != 0xcafebabe){
		printf("ERRO: Object.class invalido.\nAssinatura \"cafe babe\" nao encontrada");
		exit(0);
	}
	classObject.minor_version = ler_u2(fp);
	classObject.major_version = ler_u2(fp);
	classObject.constant_pool_count = ler_u2(fp);
	classObject.constant_pool = (cp_info*) malloc (sizeof(cp_info)*classObject.constant_pool_count);
	loadInfConstPool (classObject.constant_pool, classObject.constant_pool_count, fp);
	classObject.access_flags = ler_u2(fp);
	classObject.this_class = ler_u2(fp);
	classObject.super_class = ler_u2(fp);
	/* Object.class nao tem interfaces nem fields, de forma que nao precisamos ler o vetor das estruturas*/
	classObject.interfaces_count = ler_u2(fp);
	classObject.interfaces = (uint16_t*) malloc (sizeof(uint16_t)*classObject.interfaces_count);
	classObject.fields_count = ler_u2(fp);
	classObject.fields = (field_info*) malloc (sizeof(field_info)*classObject.fields_count);

	classObject.methods_count = ler_u2(fp);
	classObject.methods = (method_info*) malloc (sizeof(method_info)*classObject.methods_count);
	loadObjectMethods(classObject, fp);
	
	for (int i=0;i<classObject.methods_count;i++){
		//classObject.methods[i] = ler_methods(fp, classObject.constant_pool);
	}
	
	showObjectClass();
	fclose(fp);
}

void retorneNomeClass(cFile class){}
#define EXIBIDOR_SERVER

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>

#include "leitor.h"
#include "exibidor.h"

/*CONSTANTES PARA FORMATAÇÃO DOS DADOS*/
const char *flag_name [5] = {"ACC_PUBLIC", "ACC_FINAL", "ACC_SUPER", "ACC_INTERFACE", "ACC_ABSTRACT"};
const char *type_Names [12] = {"UFT8_info", "-", "Integer_info", "Float_info", "Long_info", "Double_info", "Class_info", "String_info", "Fieldref_info", "Methodref_info", "Interface_info", "Name and Type"};

/*show_UTF8: monta e mostra a string UTF8*/
void show_UTF8 (int size, unsigned char *string){
	int i = 0;
	unsigned short aux;
	char c[255]="";
	char a[255]="";

	/*printf("   ");*/
	while(i < size){ 	/*enquanto tiver byte no array de bytes*/
		if(!(string[i] & 0x80)){ 	/*1 byte para utf-8: Se inverso é true, então caracter é representado por 0, ou seja, o bit 7 é 0*/
			a[0]=string[i];
			a[1]='\0';
			/* printf("[%c]", string[i]); */
			strcat (c, a);
		}else{	/* Caso não esteja na faixa dos caracteres "usuais" */
			if(!(string[i+1] & 0x20)){	/* para utf8 de 2 bytes */
				aux = ((string[i] & 0xf) << 6) + ((string[i+1] & 0x3f));
			}else{	/* Para utf8 de 3 byte */
				aux = ((string[i] & 0xf) << 12) + ((string[i+1] & 0x3f) << 6) + (string[i + 2] & 0x3f);
				i++;
			}
			i++;
			/* printf ("%d", aux); */
			sprintf(a, "%d", aux);
			strcat (c, a);
		}
		i++;
	}
	printf ("%s", c);
}

/* função recursiva para desreferenciar indices das constantes
** que contem strings nas suas informações.
** Recebe o indice (posição) de uma constante na tabela
** e o ponteiro para a tabela e recursivamente acessa os
** indices na tabela até chegar no indice referenciando
** estrutura UTF8 que contem a string da constante inicialmente
** passado. */
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


void infoBasic(cFile classFile){
	printf("--------------------\n");
	printf("|Informações gerais|\n");
	printf("--------------------\n\n");
	printf ("Magic number: 0x%x\n", classFile.magic);
	printf("MinVersion = %d\n", classFile.minor_version);
	printf("MajVersion = %d\n", classFile.major_version);
	printf("Constant pool count: %d\n", classFile.constant_pool_count);
	printf("Access flags: %s \n", show_flags(classFile));
	printf("This class: cp_info[%d]\n", classFile.this_class);
	/*printf ("\n%d\n", classFile.constant_pool[classFile.this_class].info[0].u2);*/
	printf("Super class: cp_info[%d]\n", classFile.super_class);
	printf("Interfaces count: %d\n", classFile.interfaces_count);
	printf("Field count: %d\n", classFile.fields_count);
	printf("Method count: %d\n", classFile.methods_count);
	printf("Attributes count: %d\n\n", classFile.attributes_count);


	/*chama a função para mostrar as flags ativas*/
	// show_flags(classFile.access_flags, splitFlags);
	/*Exibe a informação (string) da classe*/
	dereference_index_UTF8(classFile.this_class, classFile.constant_pool);
	/*Exibe a informação (string) da super_classe*/
	//dereference_index_UTF8(classFile.super_class, classFile.constant_pool);
	//showConstPool(classFile.constant_pool_count, classFile.constant_pool);
}

/* A recebe a qtd de constantes presentes na tabela do CP
** e ponteiro para a tabela dos constantes.
** Percorre a tabela e exibe toda a informação contida nela.
** %d|%d mostringa os indices na estringutura seguido das informações
** relacionadas aos stringings nas outras estringuturas.*/
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
				printf("   \t\t#%d\t\t", constPool[i].info[0].u2);
				dereference_index_UTF8 (i, constPool);
				break;

			case INTERFACE_REF:
			case FIELD_REF:
			case METHOD_REF:
				printf("  \t\t#%d|#%d\t", constPool[i].info[0].u2, constPool[i].info[1].u2);
				dereference_index_UTF8(i, constPool);
				break;

			case NAME_AND_TYPE:
				printf("  \t\t#%d|#%d\t",  constPool[i].info[0].u2, constPool[i].info[1].u2);
				dereference_index_UTF8(i, constPool);
				break;
		}
		printf("\n");
	}
}

char* show_flags(cFile classFile){
	static char s[60];
	sprintf (s, "0x%04x", classFile.access_flags);

	if (classFile.access_flags & 0x01){
		strcat (s, "[public]");
	}
	if (classFile.access_flags & 0x010){
		strcat (s, "[final]");
	}
	if (classFile.access_flags & 0x020){
		strcat (s, "[super]");
	}
	if (classFile.access_flags & 0x0200){
		strcat (s, "[interface]");
	}
	if (classFile.access_flags & 0x0400){
		strcat (s, "[abstract]");
	}
	return s;
}

/*mostringa as flags do campo verificando todas as flags presentes no field*/
void show_field_flags(unsigned short flags){
	bool first = true;

	if(flags & 0x01){
		if(first){
			printf(" \tFlags: ");
			first = false;
		}else{
			printf(", ");
		}
		printf("[ACC_PUBLIC]");
	}

	if(flags & 0x02){
		if(first){
			printf(" \tFlags: ");
			first = false;
		}else{
			printf(", ");
		}
		printf("[ACC_PRIVATE]");
	}

	if(flags & 0x04){
		if(first){
			printf(" \tFlags: ");
			first = false;
		}else{
			printf(", ");
		}
		printf("[ACC_PROTECTED]");
	}

	if(flags & 0x08){
		if(first){
			printf(" \tFlags: ");
			first = false;
		}else{
			printf(", ");
		}
		printf("[ACC_STATIC]");
	}

	if(flags & 0x010){
		if(first){
			printf(" \tFlags: ");
			first = false;
		}else{
			printf(", ");
		}
		printf("[ACC_FINAL]");
	}

	if(flags & 0x0040){
		if(first){
			printf(" \tFlags: ");
			first = false;
		}else{
			printf(", ");
		}
		printf("[ACC_VOLATILE]");
	}

	if(flags & 0x0080){
		if(first){
			printf(" \tFlags: ");
			first = false;
		}else{
			printf(", ");
		}
		printf("[ACC_TRANSIENT]");
	}

	if(flags & 0x1000){
		if(first){
			printf(" \tFlags: ");
			first = false;
		}else{
			printf(", ");
		}
		printf("[ACC_SYNTHETIC]");
	}

	if(flags & 0x4000){
		if(first){
			printf(" \tFlags: ");
			first = false;
		}else{
			printf(", ");
		}
		printf("[ACC_ENUM]");
	}

	printf("\n");
}

void show_field_attribute(cp_info *cp, attribute_info attribute){
	printf(" \n\tNome do atributo: ");
	dereference_index_UTF8(attribute.attribute_name_index, cp);

	printf("\n");
	printf(" \tTamanho: %d", attribute.attribute_length);

	/*Completar a função para diferente tipos de atributo*/
}

/*Mostringa um field*/
void show_fields (cp_info *cp, field_info fields){
	/*mostringa flags*/
	show_field_flags(fields.access_flags);

	printf(" \tNome do campo: ");
	dereference_index_UTF8(fields.name_index, cp);
	printf("\n");

	printf(" \tDescriptor do campo: ");
	dereference_index_UTF8(fields.descriptor_index, cp);
	printf("\n");

	printf(" \tNumero de atributos: %d\n", fields.attribute_count);
	for (int i = 0; i < fields.attribute_count; ++i){
		printf(" Atributo[%d]: ", i);
		show_field_attribute(cp, fields.attributes[i]);
	}
}

void show_method_flags(unsigned short flags){
	/*bool first = true;*/

	if(flags & 0x0001){
		printf("[ACC_PUBLIC] ");
	}
	if(flags & 0x0002){
		printf("[ACC_PRIVATE] ");
	}
	if(flags & 0x0004){
		printf("[ACC_PROTECTED] ");
	}
	if(flags & 0x0008){
		printf("[ACC_STATIC] ");
	}
	if(flags & 0x0010){
		printf("[ACC_FINAL] ");
	}
	if(flags & 0x0020){
		printf("[ACC_SYNCHRONIZED] ");
	}
	if(flags & 0x0040){
		printf("[ACC_BRIDGE] ");
	}
	if(flags & 0x0080){
		printf("[ACC_VARARGS] ");
	}
	if(flags & 0x0100){
		printf("[ACC_NATIVE] ");
	}
	if(flags & 0x0400){
		printf("[ACC_ABstringACT] ");
	}
	if(flags & 0x0800){
		printf("[ACC_stringICT] ");
	}
	if(flags & 0x1000){
		printf("[ACC_SYNTHETIC] ");
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
		printf("\tAtributo [%d]: ", i+1);
		show_field_attribute(cp, method.attributes[i]);
		printf("\n");
	}
}


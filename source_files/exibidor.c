#define EXIBIDOR_SERVER
#include "../headers/exibidor.h"
#include "../headers/instructions.h"

/*CONSTANTES PARA FORMATAÇÃO DOS DADOS*/
const char *flag_name [5] = {"ACC_PUBLIC", "ACC_FINAL", "ACC_SUPER", "ACC_INTERFACE", "ACC_ABSTRACT"};
const char *type_Names [12] = {"UFT8_info", "-", "Integer_info", "Float_info", "Long_info", "Double_info", "Class_info", "String_info", "Fieldref_info", "Methodref_info", "Interface_info", "Name and Type"};

/*show_UTF8: monta e mostringa a stringing UTF8*/
void show_UTF8 (int size, unsigned char *string){
	int i = 0;

	/*printf("   ");*/
	while(i < size){ 	/*enquanto tiver byte no array de bytes*/
		if(!(string[i] & 0x80)){ 	/*1 byte para utf-8: Se inverso é true, então caracter é representado por 0, ou seja, o bit 7 é 0*/
			printf("%c", string[i]);
		}else{	/*Caso não esteja na faixa dos caracteres "usuais"*/
			unsigned short aux;
			if(!(string[i+1] & 0x20)){	/* para utf8 de 2 bytes */
				aux = ((string[i] & 0xf) << 6) + ((string[i+1] & 0x3f));
			}else{	/*para utf8 de 3 byte*/
				aux = ((string[i] & 0xf) << 12) + ((string[i+1] & 0x3f) << 6) + (string[i + 2] & 0x3f);
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

void infoBasic(cFile classFile){
	printf("--------------------\n");
	printf("|Informações gerais|\n");
	printf("--------------------\n\n");

	printf ("Magic number: 0x%x\n", classFile.magic);
	printf("MinVersion = %d\n", classFile.minor_version);
	printf("MajVersion = %d\n", classFile.major_version);
	printf("Constant pool count: %d\n", classFile.constant_pool_count);
	printf("Access flags: %s \n", show_flags(classFile));
	printf("This class: cp_info[%d] ", classFile.this_class);
	printf ("<");
	dereference_index_UTF8(classFile.this_class, classFile.constant_pool);
	printf (">\n");

	printf("Super class: cp_info[%d]", classFile.super_class);
	printf ("<");
	dereference_index_UTF8(classFile.super_class, classFile.constant_pool);
	printf (">\n");

	printf("Interfaces count: %d\n", classFile.interfaces_count);
	printf("Field count: %d\n", classFile.fields_count);
	printf("Method count: %d\n", classFile.methods_count);
	/*show_methods(classFile);*/
	printf("Attributes count: %d\n", classFile.attributes_count);
	/*show_cFile_attributes(classFile);*/
}

/* A recebe a qtd de constantes presentes na tabela do CP
** e ponteiro para a tabela dos constantes.
** Percorre a tabela e exibe toda a informação contida nela.
** %d|%d mostringa os indices na estringutura seguido das informações
** relacionadas aos stringings nas outras estringuturas.*/
void showConstPool(int const_pool_cont, cp_info *constPool){

	printf("\n\nPool de Constantes:\n");

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
				printf("\t\t%ld", convert_u4_toLong(constPool[i].info[0], constPool[i].info[1]));
				break;
			
			case DOUBLE:
				printf("\t\t%lf", convert_u4_toDouble(constPool[i].info[0], constPool[i].info[1]));
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
	printf("\n");
}

/* Retorna string com flags ativas */
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

/* Mostra as flags do campo verificando todas as flags presentes no field */
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

void show_field_attribute(cp_info *cp, AT_ConstantValue att_ctv){

	if(att_ctv.attribute_length == 2){
		printf(" \n\tNome do atributo: ");
		dereference_index_UTF8(att_ctv.attribute_name_index, cp);

		printf("\n");
		printf(" \tAttribute length: %d\n", att_ctv.attribute_length);
	}else{
		printf("ERROR! Attribute length do field != 2\n");
		exit(-1);
	}
}

void show_method_attribute(cp_info *cp, AT_Code att_code){
	int i = 0, aux = 0, byte_preenchimento, match_offset;
	uint32_t npairs = 0, match_atual, offset_do_match;
	// int32_t match_atual;
	uint32_t low = 0, high = 0, defaultbyte = 0, offset;
	AllIns decode[NUM_INSTRUC];
	mount_inst_array(decode);

	printf(" \n\tNome do atributo: ");
	dereference_index_UTF8(att_code.attribute_name_index, cp);

	printf("\n");
	printf(" \tAttribute length: %d\n", att_code.attribute_length);

	/*Completar a função para diferente tipos de atributo*/
	if(strcmp((char *) cp[att_code.attribute_name_index].info[1].array, "Code") == 0){
		printf("\tmax_stack = %d\n", att_code.max_stack);
		printf("\tmax_locals = %d\n", att_code.max_locals);
		printf("\tcode_length = %d\n", att_code.code_length);
		printf("\topcde = %x\n", att_code.code[i]);
		printf("\tInstrução: %s\n", decode[att_code.code[i]].name);
		
		if(decode[att_code.code[i]].bytes != 0){
			aux = i;
			for(int x = 0; x < decode[att_code.code[i]].bytes; x++)
				aux++;
		}

		for(int i = (aux+1); i < att_code.code_length; ){

			if(att_code.code[i] == TABLESWITCH){
				i++;
				byte_preenchimento = (4 - (i % 4)) % 4;
				for(int x = 0; x < byte_preenchimento; x++)
					i++;
				for(int x = 0; x < 4; x++){
					defaultbyte = (defaultbyte << 8) + att_code.code[i];
					i++;
				}
				
				for(int x = 0; x < 4; x++){
					low = (low << 8) + att_code.code[i];
					i++;
				}

				for(int x = 0; x < 4; x++){
					high = (high << 8) + att_code.code[i];
					i++;
				}

				printf("\tTableswitch %d to %d\n", low, high);
				
				match_offset = high - low + 1;
				for(int x = 0; x < match_offset; x++){
					printf("\t\t %d: ", x);
					for (int j = 0; j < 4; j++){
						offset = att_code.code[i];
						i++;
					}
					printf("\t %d(+%d)\n", (1+offset), offset);
				}

				printf("\t\tdefault: %d(+%d)\n", (1+defaultbyte), defaultbyte);

			}else if(att_code.code[i] == LOOKUPSWITCH){
				i++;
				byte_preenchimento = (4 - (i % 4)) % 4;
				for(int x = 0; x < byte_preenchimento; x++)
					i++;
				for(int x = 0; x < 4; x++){
					defaultbyte = (defaultbyte << 8) + att_code.code[i];
					i++;
				}
				for(int x = 0; x < 4; x++){
					npairs = (npairs << 8) + att_code.code[i];
					i++;
				}

				printf("\tLookupswitch %d:\n", npairs);

				for(uint32_t x = 0; x < npairs; x++){
					for(int j = 0; j < 4; j++){
						match_atual = (match_atual << 8) + att_code.code[i];
						i++;	
					}
					for (int j = 0; j < 4; j++){
						offset_do_match = att_code.code[i];
						i++;
					}
					printf("\t\t%d:\t %d(+%d)\n", match_atual, (offset_do_match+1), offset_do_match);
				}
				printf("\t\tdefault: %d(+%d)\n", (1+defaultbyte), defaultbyte);
				
			}else if(att_code.code[i] == WIDE){
				printf("WIDE...\n");
				i++;
				if(att_code.code[i] == IINC){
					printf("IINC...\n");
					i++;
				}else if(att_code.code[i] == ALOAD || att_code.code[i] == FLOAD || att_code.code[i] == ILOAD || att_code.code[i] == DLOAD || \
						att_code.code[i] == ISTORE || att_code.code[i] == LSTORE || att_code.code[i] == ASTORE || att_code.code[i] == FSTORE || \
						att_code.code[i] == RET || att_code.code[i] == DSTORE || att_code.code[i] == LLOAD)
				{
					printf("ALGUM I/FLOAD...\n");
					i++;
				}
			}else{
				printf("\tInstrução %s\n", decode[att_code.code[i]].name);
				if(decode[att_code.code[i]].bytes != 0){
					int aux = i;
					for(int x = 0; x < decode[att_code.code[aux]].bytes; x++)
						i++;
				}
				i++;
			}
		}
	}
}

/*Mostra um field*/
void show_fields (cp_info *cp, field_info fields){
	/*mostra flags*/
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
		show_field_attribute(cp, fields.att_ctv[i]);
	}
}

char* show_method_flags(unsigned short flags){
	static char s[160]="[";

	if(flags & 0x0001){
		strcat(s, "ACC_PUBLIC ");
	}
	if(flags & 0x0002){
		strcat(s, "ACC_PRIVATE ");
	}
	if(flags & 0x0004){
		strcat(s, "ACC_PROTECTED ");
	}
	if(flags & 0x0008){
		strcat(s, "ACC_STATIC ");
	}
	if(flags & 0x0010){
		strcat(s, "ACC_FINAL ");
	}
	if(flags & 0x0020){
		strcat(s, "ACC_SYNCHRONIZED ");
	}
	if(flags & 0x0040){
		strcat(s, "ACC_BRIDGE ");
	}
	if(flags & 0x0080){
		strcat(s, "ACC_VARARGS ");
	}
	if(flags & 0x0100){
		strcat(s, "ACC_NATIVE ");
	}
	if(flags & 0x0400){
		strcat(s, "ACC_ABSTRACT ");
	}
	if(flags & 0x0800){
		strcat(s, "ACC_STRICT ");
	}
	if(flags & 0x1000){
		strcat(s, "ACC_SYNTHETIC ");
	}
	s[strlen(s)-1]=']';
	/*printf ("%s", s);*/
	return s;
}

void show_methods(cFile classFile){
	for (int i=0;i<classFile.methods_count;i++){
		printf ("\tMethod[%d]\n", i);
		printf ("\t\tName: <%s>\n", classFile.constant_pool[classFile.methods[i].name_index].info[1].array);
		printf ("\t\tDescriptor: <%s>\n", classFile.constant_pool[classFile.methods[i].descriptor_index].info[1].array);
		printf ("\t\tAccess flags: 0x%04x [%s]\n", classFile.methods[i].access_flags, show_method_flags(classFile.methods[i].access_flags));
		for (int j=0;j<classFile.methods[i].attributes_count;j++){
			show_method_attribute(classFile.constant_pool, classFile.methods[i].att_code[j]);
		}
		printf("\n");
	}
}

void show_cFile_attributes(cFile classFile){
	char name[255];
	for (int i=0;i<classFile.attributes_count;i++){
		printf("\tattribute[%d]\t Len: %d", i, classFile.attributes[i].attribute_length);
		printf("\tcp_info[%d]\t <%s>\n\t\t", classFile.attributes[i].attribute_name_index, (char*)classFile.constant_pool[classFile.attributes[i].attribute_name_index].info[1].array);		/* REVISAR esse cast*/
		strcpy(name, (char*)classFile.constant_pool[classFile.attributes[i].attribute_name_index].info[1].array);		/* REVISAR esse cast*/
		if (!strcmp(name, "SourceFile")){
			printf("Sourcefile name index: %s\n", classFile.constant_pool[classFile.attributes[i].info[1]].info[1].array);
		}else{
			/*Atributo ainda nao tratado. Possiveis atributos do class file sao:
			InnerClasses, EnclosingMethod, SourceDebugExtension, BootstrapMethods, Module, ModulePackages, ModuleMainClass,
			Synthetic, Deprecated, Signature, RuntimeVisibleAnnotations, RuntimeInvisibleAnnotations, RuntimeVisibleTypeAnnotations, RuntimeInvisibleTypeAnnotations */
			printf("");
		}
	}
}

void show_info(){
	infoBasic(classFile);

	/*chama a função para mostrar as flags ativas*/
	/*show_flags(classFile);*/
	
	/*Exibe informações de Pool de constante*/
	showConstPool(classFile.constant_pool_count, classFile.constant_pool);
	
	show_methods(classFile);

	for(int i = 0; i < classFile.fields_count; i++){
		printf("\n\tFields[%d]:\n", i);
		show_fields(classFile.constant_pool, classFile.fields[i]);
	}
}
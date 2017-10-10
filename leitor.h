#include <stdint.h>
#ifndef LEITOR
	#define LEITOR

	#ifdef LEITOR_SERVER
		#define EXT_LEITOR
	#else
		#define EXT_LEITOR extern
	#endif


	/*struct de uniao para armazenar todos os tamanhos de variavel que serao lidos*/
	typedef union {
		unsigned char *array;	/*Ponteiro para uma strig*/
		unsigned char u1; 		/*para armazenar leitura de um byte*/
		unsigned short u2;		/*para armazenar leitura de dois byte*/
		unsigned int u4;		/*para armazenar leitura de quatro byte*/
	}classLoadrType;

	/* Structs que serao uteis */
	typedef struct {
		unsigned char tag;
		classLoadrType *info;
	}cp_info;

	typedef struct {
		unsigned short attribute_name_index;
		unsigned int attribute_length;
		unsigned char *info;
	}attribute_info;

	typedef struct {
		unsigned short access_flags;
		unsigned short name_index;
		unsigned short descriptor_index;
		unsigned short attributes_count;
		attribute_info *attributes;
	}method_info;

	typedef struct {
		unsigned short access_flags;
		unsigned short name_index;
		unsigned short descriptor_index;
		unsigned short attribute_count;
		attribute_info *attributes;
	} field_info;

	typedef struct{
		unsigned short constantvalue_index;
	}AT_ConstantValue;
	
	typedef struct{}AT_Code;

	typedef struct{
		unsigned short attribute_name_index;
		unsigned int attribute_length;
		unsigned short number_of_exceptions;
		unsigned short *exception_index_table;
	}AT_Exceptions;

	typedef struct{}AT_InnerClasses;

	/*DEFINIÇÃO DOS TIPOS POSSIVEIS DE TAGS NO POOL DE CONSTANTES*/
	#define UTF8 			1
	#define INTEGER 		3
	#define FLOAT 			4
	#define LONG 			5
	#define DOUBLE 			6
	#define CLASS 			7
	#define STRING 			8
	#define FIELD_REF 		9
	#define METHOD_REF  	10
	#define INTERFACE_REF 	11
	#define NAME_AND_TYPE 	12


	/*DEFINIÇÃO PARA TRATAMENTO DE POSSIVEIS ERROS*/
	#define MISSING_ARGUMENT 1
	#define CANT_OPEN 		 2
	#define INVALID_FILE 	 3
	#define UNKNOWN_TYPE 	 4

	/*CONSTANTES PARA FORMATAÇÃO DOS DADOS*/
	const char *type_Names [12] = {"UFT8_info", "-", "Integer_info", "Float_info", "Long_info", "Double_info", "Class_info", "String_info", "Fieldref_info", "Methodref_info", "Interface_info", "Name and Type"};
	const char *flag_name [5] = {"ACC_PUBLIC", "ACC_FINAL", "ACC_SUPER", "ACC_INTERFACE", "ACC_ABSTRACT"};

	EXT_LEITOR unsigned short ler_u2 (FILE *fp);
	EXT_LEITOR unsigned char ler_u1 (FILE *fp);
	EXT_LEITOR unsigned int ler_u4(FILE *fp);
	EXT_LEITOR field_info ler_fields (FILE *fp);
	EXT_LEITOR attribute_info ler_attribute(FILE *fp);
	EXT_LEITOR void show_method_flags(unsigned short flags);
	EXT_LEITOR unsigned char * ler_UTF8 (int size, FILE *fp);
	EXT_LEITOR int loadInfConstPool (cp_info *constPool, int const_pool_cont, FILE *fp);
	EXT_LEITOR void show_UTF8 (int size, unsigned char * str);	
	EXT_LEITOR void dereference_index_UTF8 (int index, cp_info *cp);
	EXT_LEITOR void showConstPool(int const_pool_cont, cp_info *constPool);
	EXT_LEITOR void show_flags(uint16_t access_flags, bool *flags);
	EXT_LEITOR float convert_u4_toFloat(classLoadrType ent);
	EXT_LEITOR long convert_u4_toLong (classLoadrType entHigh, classLoadrType entLow);
	EXT_LEITOR double convert_u4_toDouble(classLoadrType entHigh, classLoadrType entLow);
	EXT_LEITOR void loadInterfaces(uint16_t *interfaces, int interfaces_count, cp_info *constPool, FILE *fp);
	EXT_LEITOR method_info ler_methods(FILE *fp);
	EXT_LEITOR void show_methods(cp_info *cp, method_info method);
	EXT_LEITOR void show_field_flags(unsigned short flags);
	EXT_LEITOR void show_field_attribute(cp_info *cp, attribute_info attribute);
	EXT_LEITOR void show_fields(cp_info *cp, field_info field);
#endif
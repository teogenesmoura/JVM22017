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
		uint8_t *array;		/*Ponteiro para uma strig*/
		uint8_t u1; 		/*para armazenar leitura de um byte*/
		uint16_t u2;		/*para armazenar leitura de dois byte*/
		uint32_t u4;		/*para armazenar leitura de quatro byte*/
	}classLoadrType;

	/* Structs que serao uteis */
	typedef struct {
		uint8_t tag;
		classLoadrType *info;
	}cp_info;

	typedef struct {
		uint16_t attribute_name_index;
		uint32_t attribute_length;
		uint8_t *info;
	}attribute_info;

	typedef struct {
		uint16_t access_flags;
		uint16_t name_index;
		uint16_t descriptor_index;
		uint16_t attributes_count;
		attribute_info *attributes;
	}method_info;

	typedef struct {
		uint16_t access_flags;
		uint16_t name_index;
		uint16_t descriptor_index;
		uint16_t attribute_count;
		attribute_info *attributes;
	} field_info;

	typedef struct{
		unsigned short attribute_name_index;
		unsigned int attribute_length;
		uint16_t constantvalue_index;
	}AT_ConstantValue;
	
	typedef struct{
		unsigned short attribute_name_index;
		unsigned int attribute_length;
		unsigned short max_stack;
		unsigned short max_locals;
		unsigned int conde_length;
		unsigned char *conde;
		unsigned short exception_table_length;
		struct{
			unsigned short start_pc;
			unsigned short end_pc;
			unsigned short handler_pc;
			unsigned short catch_type;
		} *exception_table;
		unsigned short attribute_count;
		attribute_info *attributes;
	}AT_Code;

	typedef struct{
		uint16_t attribute_name_index;
		uint32_t attribute_length;
		uint16_t number_of_exceptions;
		uint16_t *exception_index_table;
	}AT_Exceptions;

	typedef struct{}AT_InnerClasses;

	typedef struct{
		uint32_t magic;
		uint16_t minor_version;
		uint16_t major_version;
		uint16_t constant_pool_count;
		cp_info *constant_pool;
		uint16_t access_flags;
		uint16_t this_class;
		uint16_t super_class;
		uint16_t interfaces_count;
		uint16_t *interfaces;
		uint16_t fields_count;
		field_info *fields;
		uint16_t methods_count;
		method_info *methods;
		uint16_t attributes_count;
		attribute_info *attributes;
	}cFile;


	/*DEFINIÇÃO PARA TRATAMENTO DE POSSIVEIS ERROS*/
	#define MISSING_ARGUMENT 1
	#define CANT_OPEN 		 2
	#define INVALID_FILE 	 3
	#define UNKNOWN_TYPE 	 4


	EXT_LEITOR uint16_t ler_u2 (FILE *fp);
	EXT_LEITOR int init_leitor(FILE *fp);
	EXT_LEITOR uint8_t ler_u1 (FILE *fp);
	EXT_LEITOR uint32_t ler_u4(FILE *fp);
	EXT_LEITOR field_info ler_fields (FILE *fp);
	EXT_LEITOR attribute_info ler_attribute(FILE *fp);
	EXT_LEITOR uint8_t * ler_UTF8 (int size, FILE *fp);
	EXT_LEITOR int loadInfConstPool (cp_info *constPool, int const_pool_cont, FILE *fp);
	EXT_LEITOR void dereference_index_UTF8 (int index, cp_info *cp);
	EXT_LEITOR float convert_u4_toFloat(classLoadrType ent);
	EXT_LEITOR long convert_u4_toLong (classLoadrType entHigh, classLoadrType entLow);
	EXT_LEITOR double convert_u4_toDouble(classLoadrType entHigh, classLoadrType entLow);
	EXT_LEITOR void loadInterfaces(uint16_t *interfaces, int interfaces_count, cp_info *constPool, FILE *fp);
	EXT_LEITOR void ler_methods(cFile *classFile, FILE *fp);
	EXT_LEITOR int findMain (cFile classFile);
#endif
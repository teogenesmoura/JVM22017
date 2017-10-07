#ifndef LEITOR
	#define LEITOR

	#ifdef LEITOR_SERVER
		#define EXT_LEITOR
	#else
		#define EXT_LEITOR extern
	#endif
	
	/*struct de uniao para armazenar todos os tamanhos de variavel que
	**serao lidos*/
	typedef union {
		unsigned char *array;	/*Ponteiro para uma string*/
		unsigned char u1; 		/*para armazenar leitura de um byte*/
		unsigned short u2;		/*para armazenar leitura de dois byte*/
		unsigned int u4;		/*para armazenar leitura de quatro byte*/
	}classLoadrType;

	/*uma struct para armazenar informações da cp_info*/
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
		unsigned short access_flags, name_index, descriptor_index, attributes_count;
		attribute_info *attributes;
	}method_info;


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

	EXT_LEITOR unsigned short lerU2 (FILE *fp);
	EXT_LEITOR unsigned char lerU1 (FILE *fp);
	EXT_LEITOR unsigned char * ler_UTF8 (int size, FILE *fp);
	EXT_LEITOR int loadInfConstPool (cp_info *constPool, int const_pool_cont, FILE *fp);
	EXT_LEITOR void show_UTF8 (int size, unsigned char * str);	
	EXT_LEITOR void dereference_index_UTF8 (int index, cp_info *cp);
	EXT_LEITOR void showConstPool(int const_pool_cont, cp_info *constPool);
	EXT_LEITOR float convert_u4_toFloat(classLoadrType ent);
	EXT_LEITOR long convert_u4_toLong (classLoadrType entLow, classLoadrType entHigh);
	EXT_LEITOR double convert_u4_toDouble(classLoadrType entLow, classLoadrType entHigh);
#endif
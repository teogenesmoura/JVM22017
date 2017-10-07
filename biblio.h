#include <stdio.h>
#include <stdint.h>
/*
#define u1 uint8_t
#define u2 uint16_t
#define u4 uint32_t
*/

/* Pool de constantes, de acordo com a Tabela 4.4 na pag 79*/
#define CONSTANT_Class 					7
#define CONSTANT_Fieldref				9
#define CONSTANT_Methodref 				10
#define CONSTANT_InterfaceMethodref		11
#define CONSTANT_String					8
#define CONSTANT_Integer				3
#define CONSTANT_Float					4
#define CONSTANT_Long					5
#define CONSTANT_Double					6
#define CONSTANT_NameAndType			12
#define CONSTANT_Utf8					1
#define CONSTANT_MethodHandle			15
#define CONSTANT_MethodType				16
#define CONSTANT_InvokeDynamic			18

typedef struct classinfo{	/* Secao 4.4.1 */

	uint16_t name_index;
} CONSTANT_Class_info;

typedef struct fieldrefinfo{	/* Secao 4.4.2 */
	uint16_t class_index;
	uint16_t name_and_type_index;
}CONSTANT_Fieldref_info;

typedef struct methodrefinfo{	/* Secao 4.4.2 */
	uint16_t class_index;
	uint16_t name_and_type_index;
}CONSTANT_Methodref_info;

typedef struct interfacemethodrefinfo{	/* Secao 4.4.2 */
	uint16_t class_index;
	uint16_t name_and_type_index;
}CONSTANT_InterfaceMethodref_info;

typedef struct stringinfo{	/* Secao 4.4.3 */

	uint16_t string_index;
}CONSTANT_String_info;

typedef struct integerinfo{		/* Secao 4.4.4 */

	uint32_t bytes;
}CONSTANT_Integer_info;

typedef struct floatinfo{	/* Secao 4.4.4 */

	uint32_t bytes;
}CONSTANT_Float_info;

typedef struct longinfo{	/* Secao 4.4.5 */
	uint32_t high_bytes;
	uint32_t low_bytes;
}CONSTANT_Long_info;

typedef struct doubleinfo{	/* Secao 4.4.5 */
	uint32_t high_bytes;
	uint32_t low_bytes;
}CONSTANT_Double_info;

typedef	struct nameandtypeinfo{	/* Secao 4.4.6 */
	uint16_t name_index;
	uint16_t descriptor_index;
}CONSTANT_NameAndType_info;

typedef struct utf8info{	/* Secao 4.4.7 */
	uint16_t length;
	uint8_t *bytes;
}CONSTANT_Utf8_info;

typedef struct methodhandleinfo{	/* Secao 4.4.8 */
	uint8_t reference_kind;
	uint16_t reference_index;
}CONSTANT_MethodHandle_info;

typedef struct methodtypeinfo{	/* Secao 4.4.9 */

	uint16_t descriptor_index;
}CONSTANT_MethodType_info;

typedef struct invokedynamicinfo{	/* Secao 4.4.10 */
	uint16_t bootstrap_method_attr_index;
	uint16_t name_and_type_index;
}CONSTANT_InvokeDynamic_info;

typedef struct tipoCP{			// como especificado em 4.4
	uint8_t tag;
	union{
		CONSTANT_Class_info Class;
		CONSTANT_Fieldref_info Field;
		CONSTANT_Methodref_info Method;
		CONSTANT_InterfaceMethodref_info InterfaceMethodref;
		CONSTANT_String_info String;
		CONSTANT_Integer_info Integer;
		CONSTANT_Float_info Float;
		CONSTANT_Long_info Long;
		CONSTANT_Double_info Double;
		CONSTANT_NameAndType_info NameAndType;
		CONSTANT_Utf8_info Utf8;
		CONSTANT_MethodHandle_info MethodHandle;
		CONSTANT_MethodType_info MethodType;
		CONSTANT_InvokeDynamic_info InvokeDynamic;
		// pra cada struct acima vai aparecer um novo elemento nessa union
	};
}cp_info;

typedef struct tipo_class{		// como especificado em 4.1
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
}tipoClass;



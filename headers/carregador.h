/*Area de methods:
** - armazena estruturas por classe como o conjunto de constante (constant pool) de tempo de execução, fields e dados do metodo, e code para metodo e construtores, incluindo metodos especial usado na inicialização da classe de instância e na inicialização de interfaces.

** - É criado no inicio da JVM*/

/*estrutura contendo estruturas por classe*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "../headers/leitor.h"

#ifndef CARREGADOR
	#define CARREGADOR

	#ifdef CARREGADOR_SERVER
		#define EXT_CARREGADOR
	#else
		#define EXT_CARREGADOR extern
	#endif

	typedef struct{
		cFile *tabela_classe;
		int count_class;
	}method_area;
	method_area methodArea;

	EXT_CARREGADOR int32_t java_lang_object(char * ObjectClass);
	EXT_CARREGADOR char *retorneNomeClass(cFile class);
#endif
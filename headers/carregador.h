/*
* Area de methods: armazena estruturas por classe como o conjunto de constante (constant pool) de tempo de execução,
* fields e dados do metodo, e code para metodo e construtores, incluindo metodos 'special' usados na inicialização
* da classe de instância e na inicialização de interfaces.
* 
* é criada no inicio da JVM
*/

/* estrutura contendo estruturas por classe */
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
		int class_count;
	}tipoMethodArea;

	tipoMethodArea methodArea;
	cFile classObject;
	
	EXT_CARREGADOR void java_lang_object();
	EXT_CARREGADOR void retorneNomeClass(cFile class);
#endif
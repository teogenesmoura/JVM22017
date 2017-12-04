#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>

#include "../headers/leitor.h"
#include "../headers/instructions.h"

#ifndef FRAME
	#define FRAME

	#ifdef FRAME_SERVER
		#define EXT_FRAME
	#else 
		#define EXT_FRAME extern
	#endif
	
	typedef struct frame{
		/*
		1 frame = "array of local variables, an operand stack and a reference to the constant pool of the class of current method"
		No caso, incluimos uma referencia pro proximo frame tambem.
		*/

		int32_t *variables;			/* Array de variaveis locais */
		Node *operandStack;			/* Pilha de operandos, tipo 'Node' */
		int32_t *operandArray; 		/* Array de operandos, como uma alternativa p/ arrumar os erros da pilha. */
		int tamanhoArray;			/* Variavel que controla qual a posicao atual do array. */
		cp_info *constant_pool;		/* Referencia para a constant pool, que nesse escopo provavelmente nem precisa ter, mas pra atender melhor a especificacao... */

		int ownIndex;				/* EXTRA: Indice (constant_pool) do metodo relativo a esse frame */
 		int pc;						/* EXTRA: Program counter pra manter controle de qual instrucao esta sendo executada */
		int code_length;			/* EXTRA: Code Length desse frame. Eh possivel pegar ele pelo 'ownIndex' usando a variavel classFile, mas eh mais simples ter essa variavel aqui.*/
		uint8_t *code;				/* EXTRA: Conteúdo do atributo code do metodo */
		uint16_t max_stack;			/* EXTRA: Quantidade maxima de elementos na pilha de operandos */
		uint16_t max_locals;		/* EXTRA: Quantidade maxima de elementos do vetor de variaveis locais */

		struct frame *next;
	}tipoStackFrame;

	typedef struct objeto{
		cFile* classe;
		//uint32_t* campos;
		//uint32_t* indiceCampos;
		struct objeto* superClasse;
	}objeto;


	struct frame *stackFrame;
	struct frame *currentFrame;

	EXT_FRAME int findMain();
	EXT_FRAME int isEmpty(tipoStackFrame* stackFrame);
	EXT_FRAME void initStackFrame();
	EXT_FRAME void pushFrame(tipoStackFrame* stackFrame, int methodIndex);
	EXT_FRAME void popFrame(tipoStackFrame* stackFrame);
	EXT_FRAME int sizeStackFrame(tipoStackFrame* stackFrame);
	EXT_FRAME void showStackFrame(tipoStackFrame* stackFrame);
#endif
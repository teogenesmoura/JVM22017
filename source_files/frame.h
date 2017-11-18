#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>

#include "../headers/leitor.h"

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
		int32_t *operandStack;		/* Talvez isso precise de uma estrutura propria, mas acredito que nao. */
		cp_info *constant_pool;		/* Referencia para a constant pool, que nesse escopo provavelmente nem precisa ter, mas pra atender melhor a especificacao... */
		int ownIndex;				/* EXTRA: Indice (constant_pool) do metodo relativo a esse frame */
		struct frame *next;
	}tipoStackFrame;


	EXT_FRAME int findMain();
	EXT_FRAME int isEmpty(tipoStackFrame* stackFrame);
	EXT_FRAME void initStackFrame();
	EXT_FRAME void pushFrame(tipoStackFrame* stackFrame, int methodIndex);
	EXT_FRAME void popFrame(tipoStackFrame* stackFrame);
	EXT_FRAME int sizeStackFrame(tipoStackFrame* stackFrame);
	EXT_FRAME void showStackFrame(tipoStackFrame* stackFrame);
#endif
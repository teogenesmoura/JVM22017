
#define FRAME_SERVER
#include "../headers/frame.h"
#include "../headers/leitor.h"


int findMain (){
	int i=0;
	while (i<classFile.methods_count){
		if (strcmp((char *)classFile.constant_pool[(classFile.methods[i].name_index)].info[1].array, "main")==0){
			return i;
		}
		i++;
	}
	return -1;
}

int isEmpty(tipoStackFrame* stackFrame){
	return stackFrame->next == NULL? 1:0;
}

void pushFrame(tipoStackFrame* stackFrame, int methodIndex){
	tipoStackFrame* newFrame = (tipoStackFrame*) malloc (sizeof(tipoStackFrame));
	if (!newFrame){
		printf ("Erro na alocacao de memoria!\n");
	}else{
		/* Inicializacao dos tres componentes principais do frame: local variables, operandStack e constantPool... */
		/* Vetor de variaveis locais alocado pelo max_locals do CODE do metodo em questao. */
		newFrame->variables = 	(int32_t*) malloc (sizeof(int32_t)*classFile.methods[methodIndex].att_code->max_locals);
		/* Pilha de operandos alocada pelo max_stack do atributo CODE do metodo especificado. */
		newFrame->operandStack = (int32_t*) malloc (sizeof(int32_t)*classFile.methods[methodIndex].att_code->max_stack);
		newFrame->constant_pool = classFile.constant_pool;

		/* Inicializacao dos componentes EXTRAS do frame, que foram inseridos para facilitar a implementacao da JVM*/
		newFrame->ownIndex = methodIndex;
		newFrame->pc = 0;
		newFrame->code_length = classFile.methods[methodIndex].att_code->code_length;
		if (isEmpty(stackFrame)){
			newFrame->next = NULL;
		}else{
			newFrame->next = stackFrame->next;
		}
		stackFrame->next = newFrame;
	}
}

void popFrame(tipoStackFrame* stackFrame){
	tipoStackFrame *old = (tipoStackFrame*) malloc (sizeof(tipoStackFrame));
	if (!isEmpty(stackFrame)){
		old=stackFrame->next;
		stackFrame->next = old->next;
	}
	free(old);
}

int sizeStackFrame(tipoStackFrame* stackFrame){
	int c =0;
	tipoStackFrame *w;

	w=stackFrame->next;
	while (w!=NULL){
		c+=1;
		w=w->next;
	}
	return c;
}

void showStackFrame(tipoStackFrame* stackFrame){
	/* Nao mover essa funcao pro exibidor! */
	printf ("O stackFrame tem %d frame(s).\n", sizeStackFrame(stackFrame));
	tipoStackFrame *w;
	w=stackFrame;
	if (!isEmpty(w)){
		w = stackFrame->next;
		printf (">\t");
		do{
			printf ("%s\n\t", w->constant_pool[(classFile.methods[w->ownIndex].name_index)].info[1].array);
			w = w->next;
		}while (w!=NULL);
		printf ("\n");
	}
}

void executeFrame(tipoStackFrame* stackFrame){
	currentFrame = stackFrame->next;
	do{
		/* Instanciar a instrucao referente a cada instrucao usando o vetor decode. */
	}while (currentFrame->pc < currentFrame->code_length);
	/*Talvez seja bom colocar esse ponteiro currentFrame como uma variavel global.*/
}

void initStackFrame(){
	int mainIndex;
	
	stackFrame = (tipoStackFrame*) malloc (sizeof(tipoStackFrame));


	if (!stackFrame){
		printf ("Erro na alocacao de memoria");
	}else{
		stackFrame->next = NULL;
		mainIndex = findMain();
		if (mainIndex==-1){
			printf ("Erro: Nao ha funcao main!");
			exit(0);
		}else{
			pushFrame(stackFrame, mainIndex);	// get main index from other function
		}
	}
	/* Uma vez que o stackFrame foi inicializado, ele pode ser exibido e entao, executado.*/
	showStackFrame(stackFrame);
}

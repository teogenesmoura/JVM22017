#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <inttypes.h>
#include <math.h>

#ifdef NAN
/* NAN is supported */
#endif
#ifdef INFINITY
/* INFINITY is supported */
#endif

#define NULL_REF NULL
#define MAX_LOCAL_VARIABLES 200 //Valor de u2 - int16_t
//DEFINIR O VALOR MÁXIMO DA PILHA ATRAVÉS DO CÓDIGO DO JEAN

#ifndef INSTRUCTIONS
	#define INSTRUCTIONS

	#ifdef INSTRUCTIONS_SERVER
		#define EXT_INSTRUCTIONS
	#else
		#define EXT_INSTRUCTIONS extern
	#endif

	#define	INSTRUC_NAME	35
    //#define LLONG_MAX       9223372036854775807LL
    //#define LLONG_MIN       (-LLONG_MAX - 1LL)
	typedef struct{ //Nome da struct = ""
		int32_t hexa;
		char name[INSTRUC_NAME]; //Definindo com *name cria-se uma posição na memória sendo read-only
		int8_t bytes;
		//Chamada da função
		void (*ins)();
	}AllIns; //"Abreviação" do nome struct + ""
	
	AllIns instructions[256];
	
	//Definição da pilha
	typedef struct node{
		int32_t dado;
		struct node *prox;
	}Node;

	union{
		int32_t valor0;
		int64_t valor1;
		double valor2;
		char valor3;
		char *valor4;
		float valor5;
	}conversor;
	
	//Variável que armazenará o tamanho da pilha
	int32_t tamanho_pilha;
	
// 	int32_t pc = 0;
	
	//função que irá inicializar o vetor de instruções
	//EXT_INSTRUCTIONS void init_decoder(decoder decode[]);
	
	EXT_INSTRUCTIONS void flush_in();
	//************Funções para tratamento da pilha************
	//Função para a inicialização da pilha
	EXT_INSTRUCTIONS void inicializa_pilha(Node *pilha);
	
	//Função para a alocação de um novo espaço na pilha para o empilhamento
	EXT_INSTRUCTIONS Node *aloca_elemento(int32_t dado);
	
	//Função que irá empilhar um elemento no topo da pilha
	// EXT_INSTRUCTIONS void empilha(Node *pilha, int32_t dado);
	EXT_INSTRUCTIONS void empilha(int32_t dado);
	//Função que irá desempilhar um elemento do topo da pilha
	// EXT_INSTRUCTIONS int32_t desempilha(Node *pilha);
	EXT_INSTRUCTIONS int32_t desempilha();
	//Função que verifica se a pilha está vazia
	EXT_INSTRUCTIONS int verifica_pilha_vazia(Node *pilha);

	//Função para fazer o print da pilha
	//EXT_INSTRUCTIONS void mostra_pilha(Node *pilha);
	EXT_INSTRUCTIONS void mostra_pilha();
	EXT_INSTRUCTIONS void mostra_locais();

	//Função para zerar a pilha
	EXT_INSTRUCTIONS void zera_pilha(Node *pilha);

	//Função para destruir a pilha completamente
	EXT_INSTRUCTIONS void destroi_pilha(Node *pilha);
	
	
	//***********************************************
	//CONSTANTES
	EXT_INSTRUCTIONS void nop();
	EXT_INSTRUCTIONS void aconst_null();
	EXT_INSTRUCTIONS void iconst_m1();
	EXT_INSTRUCTIONS void iconst_0();
	EXT_INSTRUCTIONS void iconst_1();
	EXT_INSTRUCTIONS void iconst_2();
	EXT_INSTRUCTIONS void iconst_3();
	EXT_INSTRUCTIONS void iconst_4();
	EXT_INSTRUCTIONS void iconst_5();
	EXT_INSTRUCTIONS void lconst_0();
	EXT_INSTRUCTIONS void lconst_1();
	EXT_INSTRUCTIONS void fconst_0();
	EXT_INSTRUCTIONS void fconst_1();
	EXT_INSTRUCTIONS void fconst_2();
	EXT_INSTRUCTIONS void dconst_0();
	EXT_INSTRUCTIONS void dconst_1();
	EXT_INSTRUCTIONS void bipush();
	EXT_INSTRUCTIONS void sipush();
	EXT_INSTRUCTIONS void ldc();
	EXT_INSTRUCTIONS void ldc_w();
	EXT_INSTRUCTIONS void ldc2_w();

	//***********************************************
	//LOADS
	EXT_INSTRUCTIONS void iload();
	EXT_INSTRUCTIONS void lload();
	EXT_INSTRUCTIONS void fload();
	EXT_INSTRUCTIONS void dload();
	EXT_INSTRUCTIONS void aload();
	EXT_INSTRUCTIONS void iload_0();
	EXT_INSTRUCTIONS void iload_1();
	EXT_INSTRUCTIONS void iload_2();
	EXT_INSTRUCTIONS void iload_3();
	EXT_INSTRUCTIONS void lload_0();
	EXT_INSTRUCTIONS void lload_1();
	EXT_INSTRUCTIONS void lload_2();
	EXT_INSTRUCTIONS void lload_3();
	EXT_INSTRUCTIONS void fload_0();
	EXT_INSTRUCTIONS void fload_1();
	EXT_INSTRUCTIONS void fload_2();
	EXT_INSTRUCTIONS void fload_3();
	EXT_INSTRUCTIONS void dload_0();
	EXT_INSTRUCTIONS void dload_1();
	EXT_INSTRUCTIONS void dload_2();
	EXT_INSTRUCTIONS void dload_3();
	EXT_INSTRUCTIONS void aload_0();
	EXT_INSTRUCTIONS void aload_1();
	EXT_INSTRUCTIONS void aload_2();
	EXT_INSTRUCTIONS void aload_3();
	EXT_INSTRUCTIONS void iaload();
	EXT_INSTRUCTIONS void laload();
	EXT_INSTRUCTIONS void faload();
	EXT_INSTRUCTIONS void daload();
	EXT_INSTRUCTIONS void aaload();
	EXT_INSTRUCTIONS void baload();
	EXT_INSTRUCTIONS void caload();
	EXT_INSTRUCTIONS void saload();

	//***********************************************
	//STORES
	EXT_INSTRUCTIONS void istore();
	EXT_INSTRUCTIONS void lstore();
	EXT_INSTRUCTIONS void fstore();
	EXT_INSTRUCTIONS void dstore();
	EXT_INSTRUCTIONS void astore();
	EXT_INSTRUCTIONS void istore_0();
	EXT_INSTRUCTIONS void istore_1();
	EXT_INSTRUCTIONS void istore_2();
	EXT_INSTRUCTIONS void istore_3();
	EXT_INSTRUCTIONS void lstore_0();
	EXT_INSTRUCTIONS void lstore_1();
	EXT_INSTRUCTIONS void lstore_2();
	EXT_INSTRUCTIONS void lstore_3();
	EXT_INSTRUCTIONS void fstore_0();
	EXT_INSTRUCTIONS void fstore_1();
	EXT_INSTRUCTIONS void fstore_2();
	EXT_INSTRUCTIONS void fstore_3();
	EXT_INSTRUCTIONS void dstore_0();
	EXT_INSTRUCTIONS void dstore_1();
	EXT_INSTRUCTIONS void dstore_2();
	EXT_INSTRUCTIONS void dstore_3();
	EXT_INSTRUCTIONS void astore_0();
	EXT_INSTRUCTIONS void astore_1();
	EXT_INSTRUCTIONS void astore_2();
	EXT_INSTRUCTIONS void astore_3();
	EXT_INSTRUCTIONS void iastore();
	EXT_INSTRUCTIONS void lastore();
	EXT_INSTRUCTIONS void fastore();
	EXT_INSTRUCTIONS void dastore();
	EXT_INSTRUCTIONS void aastore();
	EXT_INSTRUCTIONS void bastore();
	EXT_INSTRUCTIONS void castore();
	EXT_INSTRUCTIONS void sastore();


	EXT_INSTRUCTIONS void dup_();
	//***********************************************
	//OPERAÇÕES MATEMÁTICAS
	EXT_INSTRUCTIONS void iadd();
	EXT_INSTRUCTIONS void ladd();
	EXT_INSTRUCTIONS void fadd();
	EXT_INSTRUCTIONS void dadd(); 
	EXT_INSTRUCTIONS void isub(); 
	EXT_INSTRUCTIONS void lsub(); 
	EXT_INSTRUCTIONS void fsub(); 
	EXT_INSTRUCTIONS void dsub(); 
	EXT_INSTRUCTIONS void imul(); 
	EXT_INSTRUCTIONS void lmul(); 
	EXT_INSTRUCTIONS void fmul(); 
	EXT_INSTRUCTIONS void dmul(); 
	EXT_INSTRUCTIONS void idiv(); 
	EXT_INSTRUCTIONS void ldiv_();
	EXT_INSTRUCTIONS void fdiv(); 
	EXT_INSTRUCTIONS void ddiv(); 
	EXT_INSTRUCTIONS void irem(); 
	EXT_INSTRUCTIONS void lrem(); 
	EXT_INSTRUCTIONS void frem(); 
	EXT_INSTRUCTIONS void drem_();
	EXT_INSTRUCTIONS void ineg();
	EXT_INSTRUCTIONS void lneg();
	EXT_INSTRUCTIONS void fneg();
	EXT_INSTRUCTIONS void dneg();
	EXT_INSTRUCTIONS void ishl();
	EXT_INSTRUCTIONS void lshl();
	EXT_INSTRUCTIONS void ishr();
	EXT_INSTRUCTIONS void lshr();
	EXT_INSTRUCTIONS void iushr();
	EXT_INSTRUCTIONS void lushr();
	EXT_INSTRUCTIONS void iand();
	EXT_INSTRUCTIONS void land();
	EXT_INSTRUCTIONS void ior();
	EXT_INSTRUCTIONS void lor();
	EXT_INSTRUCTIONS void ixor();
	EXT_INSTRUCTIONS void lxor();
	EXT_INSTRUCTIONS void iinc();

	//***********************************************
	//CONVERSÕES
	EXT_INSTRUCTIONS void i2l();
	EXT_INSTRUCTIONS void i2f();
	EXT_INSTRUCTIONS void i2d();
	EXT_INSTRUCTIONS void l2i();
	EXT_INSTRUCTIONS void l2f();
	EXT_INSTRUCTIONS void l2d();
	EXT_INSTRUCTIONS void f2i();
	EXT_INSTRUCTIONS void f2l();
	EXT_INSTRUCTIONS void f2d(); 
	EXT_INSTRUCTIONS void d2i(); 
	EXT_INSTRUCTIONS void d2l(); 
	EXT_INSTRUCTIONS void d2f(); 
	EXT_INSTRUCTIONS void i2b(); 
	EXT_INSTRUCTIONS void i2c();
	EXT_INSTRUCTIONS void i2s();

	//***********************************************
	//COMPARAÇÕES
	EXT_INSTRUCTIONS void lcmp();
	EXT_INSTRUCTIONS void fcmpl();
	EXT_INSTRUCTIONS void fcmpg();
	EXT_INSTRUCTIONS void dcmpl();
	EXT_INSTRUCTIONS void dcmpg();
	EXT_INSTRUCTIONS void ifeq();
	EXT_INSTRUCTIONS void ifne();
	EXT_INSTRUCTIONS void iflt();
	EXT_INSTRUCTIONS void ifge();
	EXT_INSTRUCTIONS void ifgt();
	EXT_INSTRUCTIONS void ifle();
	EXT_INSTRUCTIONS void if_icmpeq();
	EXT_INSTRUCTIONS void if_icmpne();
	EXT_INSTRUCTIONS void if_icmplt();
	EXT_INSTRUCTIONS void if_icmpge();
	EXT_INSTRUCTIONS void if_icmpgt();
	EXT_INSTRUCTIONS void if_icmple();
	EXT_INSTRUCTIONS void if_acmpeq();
	EXT_INSTRUCTIONS void if_acmpne();

	//***********************************************
	//CONTROLE
	EXT_INSTRUCTIONS void goto_();
	EXT_INSTRUCTIONS void jsr();
	EXT_INSTRUCTIONS void ret();
	EXT_INSTRUCTIONS void tableswitch(); 	//VER COM MAIS CALMA COMO FAZER
	EXT_INSTRUCTIONS void lookupswitch(); 	//VER COM MAIS CALMA COMO FAZER
	EXT_INSTRUCTIONS void ireturn(); //PRECISA DO FRAME
	EXT_INSTRUCTIONS void lreturn(); //PRECISA DO FRAME
	EXT_INSTRUCTIONS void freturn(); //PRECISA DO FRAME
	EXT_INSTRUCTIONS void dreturn(); //PRECISA DO FRAME
	EXT_INSTRUCTIONS void areturn(); //PRECISA DO FRAME
	EXT_INSTRUCTIONS void return_(); //PRECISA DO FRAME

	//***********************************************
	//REFERÊNCIAS
	EXT_INSTRUCTIONS void getstatic(); //PRECISA DA CONSTANT POOL
	EXT_INSTRUCTIONS void putstatic(); 
	EXT_INSTRUCTIONS void getfield();
	EXT_INSTRUCTIONS void putfield();
	EXT_INSTRUCTIONS void invokevirtual();
	EXT_INSTRUCTIONS void invokespecial();
	EXT_INSTRUCTIONS void invokestatic();
	EXT_INSTRUCTIONS void invokeinterface();
	//EXT_INSTRUCTIONS  void invokedynamic();
	EXT_INSTRUCTIONS void new_();
	EXT_INSTRUCTIONS void newarray();
	EXT_INSTRUCTIONS void anewarray();
	EXT_INSTRUCTIONS void arraylength();
	//EXT_INSTRUCTIONS void athrow();
	//EXT_INSTRUCTIONS void checkcast();
	//EXT_INSTRUCTIONS void instanceof();
	//EXT_INSTRUCTIONS void monitorenter();
	//EXT_INSTRUCTIONS void monitorexit();

	//***********************************************
	//EXTENDIDO
	EXT_INSTRUCTIONS void wide(int32_t escolha, uint32_t opcode, uint32_t indexbyte1, uint32_t indexbyte2, uint32_t constbyte1, uint32_t constbyte2); //JUNTAR AS DUAS FUNÇÕES DO WIDE, PASSAR OS ARGUMENTOS QUE NÃO PRECISAR COM 0 E PASSAR O PRIMEIRO ARGUMENTO SENDO O DE ESCOLHA DO WIDE, DEPENDENDO DO OPCODE -> FAZER IFS DENTRO DA FUNÇÃO WIDE PARA PODER ESCOLHER QUAL INSTRUÇÃO EXECUTAR E QUAL FORMA
	EXT_INSTRUCTIONS void wide1(char *opcode); //Confirmar o funcionamento do wide
	EXT_INSTRUCTIONS void wide2(uint32_t indexbyte1, uint32_t indexbyte2, uint32_t constbyte1, uint32_t constbyte2); //Confirmar o funcionamento do wide
	EXT_INSTRUCTIONS void multianewarray(); //PRECISA DA CONSTANT POOL
	EXT_INSTRUCTIONS void ifnull();
	EXT_INSTRUCTIONS void ifnonnull();
	EXT_INSTRUCTIONS void goto_w();
	EXT_INSTRUCTIONS void jsr_w();
	//***********************************************

	//Função para criar o array de instruções
	EXT_INSTRUCTIONS void mount_inst_array();

	//Funções para mensagens de erros
	EXT_INSTRUCTIONS void internal_error();
	EXT_INSTRUCTIONS void out_of_mem();
	EXT_INSTRUCTIONS void stack__ovflw_error();
	EXT_INSTRUCTIONS void unkwn_err();
	EXT_INSTRUCTIONS void ArithmeticException();
#endif

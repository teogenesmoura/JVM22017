#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<stdint.h>
#include <unistd.h>
#include <errno.h>

typedef struct{ //Nome da struct = ""
	int32_t hexa;
	char name[20]; //Definindo com *name cria-se uma posição na memória sendo read-only
	//Chamada da função
	void (*ins)();
}AllIns; //"Abreviação" do nome struct + ""

//Funções das intruções

//***********************************************
//CONSTANTES
void nop();
void aconst_null();
void iconst_m1();
void iconst_0();
void iconst_1();
void iconst_2();
void iconst_3();
void iconst_4();
void iconst_5();
void lconst_0();
void lconst_1();
void fconst_0();
void fconst_1();
void fconst_2();
void dconst_0();
void dconst_1();
void bipush();
void sipush();
void ldc();
void ldc_w();
void ldc2_w();

//***********************************************
//LOADS
void iload();
void lload();
void fload();
void dload();
void aload();
void iload_0();
void iload_1();
void iload_2();
void iload_3();
void lload_0();
void lload_1();
void lload_2();
void lload_3();
void fload_0();
void fload_1();
void fload_2();
void fload_3();
void dload_0();
void dload_1();
void dload_2();
void dload_3();
void aload_0();
void aload_1();
void aload_2();
void aload_3();
void iaload();
void laload();
void faload();
void daload();
void aaload();
void baload();
void caload();
void saload();

//***********************************************
//STORES
void istore();
void lstore();
void fstore();
void dstore();
void astore();
void istore_0();
void istore_1();
void istore_2();
void istore_3();
void lstore_0();
void lstore_1();
void lstore_2();
void lstore_3();
void fstore_0();
void fstore_1();
void fstore_2();
void fstore_3();
void dstore_0();
void dstore_1();
void dstore_2();
void dstore_3();
void astore_0();
void astore_1();
void astore_2();
void astore_3();
void iastore();
void lastore();
void fastore();
void dastore();
void aastore();
void bastore();
void castore();
void sastore();

//***********************************************
//PILHA
// void pop();
// void pop2();
// void dup();
// void dup_x1();
// void dup_x2();
// void dup2();
// void dup2_x1();
// void dup2_x2();
// void swap();

//***********************************************
//OPERAÇÕES MATEMÁTICAS
void iadd();
void ladd();
void fadd();
void dadd();
void isub();
void lsub();
void fsub();
void dsub();
void imul();
void lmul();
void fmul();
void dmul();
void idiv();
void ldiv_();
void fdiv();
void ddiv();
void irem();
void lrem();
void frem();
void drem();
void ineg();
void lneg();
void fneg();
void dneg();
void ishl();
void lshl();
void ishr();
void lshr();
void iushr();
void lushr();
void iand();
void land();
void ior();
void lor();
void ixor();
void lxor();
void iinc();

//***********************************************
//CONVERSÕES
void i2l();
void i2f();
void i2d();
void l2i();
void l2f();
void l2d();
void f2i();
void f2l();
void f2d();
void d2i();
void d2l();
void d2f();
void i2b();
void i2c();
void i2s();

//***********************************************
//COMPARAÇÕES
void lcmp();
void fcmpl();
void fcmpg();
void dcmpl();
void dcmpg();
void ifeq();
void ifne();
void iflt();
void ifge();
void ifgt();
void ifle();
void if_icmpeq();
void if_icmpne();
void if_icmplt();
void if_icmpge();
void if_icmpgt();
void if_icmple();
void if_acmpeq();
void if_acmpne();

//***********************************************
//CONTROLES
void goto_();
void jsr();
void ret();
void tableswitch();
void lookupswitch();
void ireturn();
void lreturn();
void freturn();
void dreturn();
void areturn();
void return_();

//***********************************************
//REFERÊNCIAS
void getstatic();
void putstatic();
void getfield();
void putfield();
void invokevirtual();
void invokespecial();
void invokestatic();
void invokeinterface();
// void invokedynamic();
void new();
void newarray();
void anewarray();
void arraylength();
// void athrow();
// void checkcast();
// void instanceof();
// void monitorenter();
// void monitorexit();

//***********************************************
//EXTENDED
void wide();
void multianewarray();
void ifnull();
void ifnonnull();
void goto_w();
void jsr_w();
//***********************************************

//Função para criar o array de instruções
void mount_inst_array();

//Funções para mensagens de erros
void internal_error();
void out_of_mem();
void stack__ovflw_error();
void unkwn_err();

int main(int argc, char *argv[]){
	
// 	int8_t opcode;
	char desire[20];
	
	AllIns instructions[256];
	
	mount_inst_array(instructions);
	
// 	internal_error();
// 	out_of_mem();
// 	stack__ovflw_error();
// 	unkwn_err();
	
// 	printf("*****Instructions table*****\nQual instrução deseja?: ");
// 	scanf("%s", desire);
// 	printf("lido = |%s|\n", desire);
	
	//Mostra o diretório atual
	char cwd[1024];
	if (getcwd(cwd, sizeof(cwd)) != NULL)
// 		fprintf(stdout, "Current working dir: %s\n", cwd);
	else
// 		perror("getcwd() error");
	
 	return 0;
}

void mount_inst_array(AllIns *instructions){
	
	//instructions[0].ins(); //Chamada para a execução da instrução
	
	//ATRIBUIÇÃO DO NOP
	instructions[0].hexa = 0x00;
	strcpy(instructions[0].name, "nop");
  	instructions[0].ins = nop;
	
	//ATRIBUIÇÃO DO ACONST_NULL
	instructions[1].hexa = 0x01;
	strcpy(instructions[1].name, "aconst_null");
  	instructions[1].ins = aconst_null;
	
	//ATRIBUIÇÃO DO ICONST_M1
	instructions[2].hexa = 0x02;
	strcpy(instructions[2].name, "aconst_m1");
  	instructions[2].ins = nop;
	
	//ATRIBUIÇÃO DO ICONST_0
	instructions[3].hexa = 0x03;
	strcpy(instructions[3].name, "iconst_0");
  	instructions[3].ins = nop;
	
	//ATRIBUIÇÃO DO ICONST_1
	instructions[4].hexa = 0x04;
	strcpy(instructions[4].name, "iconst_1");
  	instructions[4].ins = nop;
	
	//ATRIBUIÇÃO DO ICONST_2
	instructions[5].hexa = 0x05;
	strcpy(instructions[5].name, "iconst_2");
  	instructions[5].ins = nop;
	
	//ATRIBUIÇÃO DO ICONST_3
	instructions[6].hexa = 0x06;
	strcpy(instructions[6].name, "iconst_3");
  	instructions[6].ins = nop;
	
	//ATRIBUIÇÃO DO ICONST_4
	instructions[7].hexa = 0x07;
	strcpy(instructions[7].name, "iconst_4");
  	instructions[7].ins = nop;
	
	//ATRIBUIÇÃO DO ICONST_5
	instructions[8].hexa = 0x08;
	strcpy(instructions[8].name, "iconst_5");
  	instructions[8].ins = nop;
	
	//ATRIBUIÇÃO DO LCONST_0
	instructions[9].hexa = 0x09;
	strcpy(instructions[9].name, "lconst_0");
  	instructions[9].ins = nop;
	
	//ATRIBUIÇÃO DO LCONST_1
	instructions[10].hexa = 0x0A;
	strcpy(instructions[10].name, "lconst_1");
  	instructions[10].ins = nop;
	
	//ATRIBUIÇÃO DO FCONST_0
	instructions[11].hexa = 0x0B;
	strcpy(instructions[11].name, "fconst_0");
  	instructions[11].ins = nop;
	
	//ATRIBUIÇÃO DO FCONST_1
	instructions[12].hexa = 0x0C;
	strcpy(instructions[12].name, "fconst_1");
  	instructions[12].ins = nop;
	
	//ATRIBUIÇÃO DO FCONST_2
	instructions[13].hexa = 0x0D;
	strcpy(instructions[13].name, "fconst_2");
  	instructions[13].ins = nop;
	
	//ATRIBUIÇÃO DO DCONST_0
	instructions[14].hexa = 0x0E;
	strcpy(instructions[14].name, "dconst_0");
  	instructions[14].ins = nop;
	
	//ATRIBUIÇÃO DO DCONST_1
	instructions[15].hexa = 0x0F;
	strcpy(instructions[15].name, "dconst_1");
  	instructions[15].ins = nop;
	
	//ATRIBUIÇÃO DO BIPUSH
	instructions[16].hexa = 0x10;
	strcpy(instructions[16].name, "bipush");
  	instructions[16].ins = nop;
	
	//ATRIBUIÇÃO DO SIPUSH
	instructions[17].hexa = 0x11;
	strcpy(instructions[17].name, "sipush");
  	instructions[17].ins = nop;
	
	//ATRIBUIÇÃO DO LDC
	instructions[18].hexa = 0x12;
	strcpy(instructions[18].name, "ldc");
  	instructions[18].ins = nop;
	
	//ATRIBUIÇÃO DO LDC_W
	instructions[19].hexa = 0x13;
	strcpy(instructions[19].name, "ldc_w");
  	instructions[19].ins = nop;
	
	//ATRIBUIÇÃO DO LDC2_w
	instructions[20].hexa = 0x14;
	strcpy(instructions[20].name, "ldc2_w");
  	instructions[20].ins = nop;
	
	//******************************************************************
	//OPCODES RESERVADOS -> Não podem aparecer em aquivos .class válidos
	//Usado para debug e pra implementar breakpoints
	instructions[202].hexa = 0xCA;
	strcpy(instructions[202].name, "breakpoint");
	
	//Instruções para fornecer backdoor
	instructions[254].hexa = 0xFE;
 	strcpy(instructions[254].name, "impdep1");
	instructions[255].hexa = 0xFF;
	strcpy(instructions[255].name, "impdep2");
	
}

void internal_error(){ printf("InternalError\n"); exit(0);}

void out_of_mem(){ printf("OutOfMemoryError\n"); exit(0);}

void stack__ovflw_error(){ printf("StackOverflowError\n"); exit(0);}

void unkwn_err(){ printf("UnknownError\n"); exit(0);}

void nop(){return;}
void aconst_null(){return;}
void iconst_m1(){return;}
void iconst_0(){return;}
void iconst_1(){return;}
void iconst_2(){return;}
void iconst_3(){return;}
void iconst_4(){return;}
void iconst_5(){return;}
void lconst_0(){return;}
void lconst_1(){return;}
void fconst_0(){return;}
void fconst_1(){return;}
void fconst_2(){return;}
void dconst_0(){return;}
void dconst_1(){return;}
void bipush(){return;}
void sipush(){return;}
void ldc(){return;}
void ldc_w(){return;}
void ldc2_w(){return;}
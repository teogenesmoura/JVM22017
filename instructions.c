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

typedef struct{ //Nome da struct = ""
	int32_t hexa;
	char name[20]; //Definindo com *name cria-se uma posição na memória sendo read-only
	int8_t byte;
	//Chamada da função
	void (*ins)();
}AllIns; //"Abreviação" do nome struct + ""

//Definição da pilha
typedef struct node{
 	int32_t dado;
	struct node *prox;
}Node;

//Variável que armazenará o tamanho da pilha
int32_t tamanho_pilha;

void flush_in();

//************Funções para tratamento da pilha************
//Função para a inicialização da pilha
void inicializa_pilha(Node *pilha);

//Função para a alocação de um novo espaço na pilha para o empilhamento
Node *aloca_elemento(int32_t dado);

//Função que irá empilhar um elemento no topo da pilha
void empilha(Node *pilha, int32_t dado);

//Função que irá desempilhar um elemento do topo da pilha
int32_t desempilha(Node *pilha);

//Função que verifica se a pilha está vazia
int verifica_pilha_vazia(Node *pilha);

//Função para fazer o print da pilha
void mostra_pilha(Node *pilha);

//Função para zerar a pilha
void zera_pilha(Node *pilha);

//Função para destruir a pilha completamente
void destroi_pilha(Node *pilha);

int32_t pc = 0;

//Funções das intruções

//***********************************************
//CONSTANTES

//Incrementa o pc
void nop();
//Coloca uma referência null no topo da pilha
void aconst_null(Node *pilha);
void iconst_m1(Node *pilha);
void iconst_0(Node *pilha);
void iconst_1(Node *pilha);
void iconst_2(Node *pilha);
void iconst_3(Node *pilha);
void iconst_4(Node *pilha);
void iconst_5(Node *pilha);
void lconst_0(Node *pilha);
void lconst_1(Node *pilha);
void fconst_0(Node *pilha);
void fconst_1(Node *pilha);
void fconst_2(Node *pilha);
void dconst_0(Node *pilha);
void dconst_1(Node *pilha);
void bipush(Node *pilha, int32_t byte);
void sipush(Node *pilha, uint32_t byte1, uint32_t byte2);
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
void iadd(Node *pilha);
void ladd(Node *pilha);
void fadd(Node *pilha);
void dadd(Node *pilha); //Testar
void isub(Node *pilha); //Testar
void lsub(Node *pilha); //Testar
void fsub(Node *pilha); //Testar
void dsub(Node *pilha); //Testar
void imul(Node *pilha); //Testar
void lmul(Node *pilha); //Testar
void fmul(Node *pilha); //Testar
void dmul(Node *pilha); //Testar
void idiv(Node *pilha); //Testar
void ldiv_(Node *pilha);//Testar
void fdiv(Node *pilha); //Testar
void ddiv(Node *pilha); //Testar
void irem(Node *pilha); //Testar
void lrem(Node *pilha); //Testar
void frem(Node *pilha); //Testar
void drem_(Node *pilha); //Testar
void ineg(Node *pilha);
void lneg(Node *pilha);
void fneg(Node *pilha);
void dneg(Node *pilha);
void ishl(Node *pilha);
void lshl(Node *pilha);
void ishr(Node *pilha);
void lshr(Node *pilha);
void iushr(Node *pilha);
void lushr(Node *pilha);
void iand(Node *pilha);
void land(Node *pilha);
void ior(Node *pilha);
void lor(Node *pilha);
void ixor(Node *pilha);
void lxor(Node *pilha);
void iinc(Node *pilha);

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
//CONTROLE
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
//EXTENDIDO
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
void ArithmeticException();

int main(int argc, char *argv[]){
	
//  	int32_t opcode;
// 	int32_t opcode, opcode2;
// 	float a = 12.2;
// 	float b= 13.3;

// 	char desire[20];
	
	system("clear");
	
	AllIns instructions[256];
	
	Node *pilha = (Node*) malloc(sizeof(Node));
	
	if (!pilha){
		printf("Sem memória disponível");
		exit(0);
	}
	
// 	int32_t variaveis_locais[MAX_LOCAL_VARIABLES];
	
	inicializa_pilha(pilha);
	
	mount_inst_array(instructions);
	
//  	instructions[97].ins();
	
	inicializa_pilha(pilha);
	
//  	for (int i = 16; i < 18; i++)
// 	instructions[98].ins(pilha);
	
// 	empilha(pilha, 2147483647)
	
// 	float c = 0.0;
// 	memcpy(&opcode, &c, sizeof(int32_t));
	empilha(pilha, 0);
	
// 	memcpy(&opcode, &a, sizeof(int32_t));
//  	printf("VALORA = %032x\n", opcode);
//    	empilha(pilha, opcode);
	empilha(pilha, 12);
	
// 	empilha(pilha, 0x22222222);
	empilha(pilha, 0);
	
// 	memcpy(&opcode2, &b, sizeof(int32_t));
// 	printf("VALORB = %032x\n", opcode2);
//    	empilha(pilha, opcode2);
	empilha(pilha, 14);
	
	instructions[99].ins(pilha);
// 	empilha(pilha, 0xDDDDDDDD);
	
//  	mostra_pilha(pilha);
	
//  	instructions[98].ins();
	
	
   	mostra_pilha(pilha);

	/*
	empilha(pilha,1);
	mostra_pilha(pilha);
	empilha(pilha,2);
	empilha(pilha,2);
	empilha(pilha,2);
	empilha(pilha,2);
	empilha(pilha,2);
	empilha(pilha,2);
	empilha(pilha,2);
	mostra_pilha(pilha);
	empilha(pilha,2);
	empilha(pilha,3);
	
	mostra_pilha(pilha);
	
	zera_pilha(pilha);
	
	mostra_pilha(pilha);
	
	desempilha(pilha);
	
	mostra_pilha(pilha);
	
	destroi_pilha(pilha);
	*/
	
// 	printf("pc = %d\n", pc);
	
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
 		fprintf(stdout, "Current working dir: %s\n", cwd);
	else
 		perror("getcwd() error");
	
 	return 0;
}

void flush_in(){ 
	
	int ch;
	while((ch = fgetc(stdin)) != EOF && ch != '\n' ){} 
}

void mount_inst_array(AllIns *instructions){
	
	//instructions[0].ins(); //Chamada para a execução da instrução
	
	char vec_strings[256][20];
	
	//******************************************************************
	//CONSTANTES
	
	strcpy(vec_strings[0], "nop");
	strcpy(vec_strings[1], "aconst_null");
	strcpy(vec_strings[2], "iconst_m1");
	strcpy(vec_strings[3], "iconst_0");
	strcpy(vec_strings[4], "iconst_1");
	strcpy(vec_strings[5], "iconst_2");
	strcpy(vec_strings[6], "iconst_3");
	strcpy(vec_strings[7], "iconst_4");
	strcpy(vec_strings[8], "iconst_5");
	strcpy(vec_strings[9], "lconst_0");
	strcpy(vec_strings[10], "lconst_1");
	strcpy(vec_strings[11], "fconst_0");
	strcpy(vec_strings[12], "fconst_1");
	strcpy(vec_strings[13], "fconst_2");
	strcpy(vec_strings[14], "dconst_0");
	strcpy(vec_strings[15], "dconst_1");
	strcpy(vec_strings[16], "bipush");
	strcpy(vec_strings[17], "sipush");
	strcpy(vec_strings[18], "ldc");
	strcpy(vec_strings[19], "ldc_w");
	strcpy(vec_strings[20], "ldc2_w");
	
	//******************************************************************
	//LOADS
	
	strcpy(vec_strings[21], "iload");
	strcpy(vec_strings[22], "lload");
	strcpy(vec_strings[23], "fload");
	strcpy(vec_strings[24], "dload");
	strcpy(vec_strings[25], "aload");
	strcpy(vec_strings[26], "iload_0");
	strcpy(vec_strings[27], "iload_1");
	strcpy(vec_strings[28], "iload_2");
	strcpy(vec_strings[29], "iload_3");
	strcpy(vec_strings[30], "lload_0");
	strcpy(vec_strings[31], "lload_1");
	strcpy(vec_strings[32], "lload_2");
	strcpy(vec_strings[33], "lload_3");
	strcpy(vec_strings[34], "fload_0");
	strcpy(vec_strings[35], "fload_1");
	strcpy(vec_strings[36], "fload_2");
	strcpy(vec_strings[37], "fload_3");
	strcpy(vec_strings[38], "dload_0");
	strcpy(vec_strings[39], "dload_1");
	strcpy(vec_strings[40], "dload_2");
	strcpy(vec_strings[41], "dload_3");
	strcpy(vec_strings[42], "aload_0");
	strcpy(vec_strings[43], "aload_1");
	strcpy(vec_strings[44], "aload_2");
	strcpy(vec_strings[45], "aload_3");
	strcpy(vec_strings[46], "iaload");
	strcpy(vec_strings[47], "laload");
	strcpy(vec_strings[48], "faload");
	strcpy(vec_strings[49], "daload");
	strcpy(vec_strings[50], "aaload");
	strcpy(vec_strings[51], "baload");
	strcpy(vec_strings[52], "caload");
	strcpy(vec_strings[53], "saload");
	
	//******************************************************************
	//STORES
	
	strcpy(vec_strings[54], "istore");
	strcpy(vec_strings[55], "lstore");
	strcpy(vec_strings[56], "fstore");
	strcpy(vec_strings[57], "dstore");
	strcpy(vec_strings[58], "astore");
	strcpy(vec_strings[59], "istore_0");
	strcpy(vec_strings[60], "istore_1");
	strcpy(vec_strings[61], "istore_2");
	strcpy(vec_strings[62], "istore_3");
	strcpy(vec_strings[63], "lstore_0");
	strcpy(vec_strings[64], "lstore_1");
	strcpy(vec_strings[65], "lstore_2");
	strcpy(vec_strings[66], "lstore_3");
	strcpy(vec_strings[67], "fstore_0");
	strcpy(vec_strings[68], "fstore_1");
	strcpy(vec_strings[69], "fstore_2");
	strcpy(vec_strings[70], "fstore_3");
	strcpy(vec_strings[71], "dstore_0");
	strcpy(vec_strings[72], "dstore_1");
	strcpy(vec_strings[73], "dstore_2");
	strcpy(vec_strings[74], "dstore_3");
	strcpy(vec_strings[75], "astore_0");
	strcpy(vec_strings[76], "astore_1");
	strcpy(vec_strings[77], "astore_2");
	strcpy(vec_strings[78], "astore_3");
	strcpy(vec_strings[79], "iastore");
	strcpy(vec_strings[80], "lastore");
	strcpy(vec_strings[81], "fastore");
	strcpy(vec_strings[82], "dastore");
	strcpy(vec_strings[83], "aastore");
	strcpy(vec_strings[84], "bastore");
	strcpy(vec_strings[85], "castore");
	strcpy(vec_strings[86], "sastore");
	
	//******************************************************************
	//PILHA
	
	strcpy(vec_strings[87], "pop");
	strcpy(vec_strings[88], "pop2");
	strcpy(vec_strings[89], "dup");
	strcpy(vec_strings[90], "dup_x1");
	strcpy(vec_strings[91], "dup_x2");
	strcpy(vec_strings[92], "dup2");
	strcpy(vec_strings[93], "dup2_x1");
	strcpy(vec_strings[94], "dup2_x2");
	strcpy(vec_strings[95], "swap");
	
	//******************************************************************
	//OPERAÇÕES MATEMÁTICAS
	
	strcpy(vec_strings[96], "iadd");
	strcpy(vec_strings[97], "ladd");
	strcpy(vec_strings[98], "fadd");
	strcpy(vec_strings[99], "dadd");
	strcpy(vec_strings[100], "isub");
	strcpy(vec_strings[101], "lsub");
	strcpy(vec_strings[102], "fsub");
	strcpy(vec_strings[103], "dsub");
	strcpy(vec_strings[104], "imul");
	strcpy(vec_strings[105], "lmul");
	strcpy(vec_strings[106], "fmul");
	strcpy(vec_strings[107], "dmul");
	strcpy(vec_strings[108], "idiv");
	strcpy(vec_strings[109], "ldiv");
	strcpy(vec_strings[110], "fdiv");
	strcpy(vec_strings[111], "ddiv");
	strcpy(vec_strings[112], "irem");
	strcpy(vec_strings[113], "lrem");
	strcpy(vec_strings[114], "frem");
	strcpy(vec_strings[115], "drem");
	strcpy(vec_strings[116], "ineg");
	strcpy(vec_strings[117], "lneg");
	strcpy(vec_strings[118], "fneg");
	strcpy(vec_strings[119], "dneg");
	strcpy(vec_strings[120], "ishl");
	strcpy(vec_strings[121], "lshl");
	strcpy(vec_strings[122], "ishr");
	strcpy(vec_strings[123], "lshr");
	strcpy(vec_strings[124], "iushr");
	strcpy(vec_strings[125], "lushr");
	strcpy(vec_strings[126], "iand");
	strcpy(vec_strings[127], "land");
	strcpy(vec_strings[128], "ior");
	strcpy(vec_strings[129], "lor");
	strcpy(vec_strings[130], "ixor");
	strcpy(vec_strings[131], "lxor");
	strcpy(vec_strings[132], "iin");
	
	//******************************************************************
	//CONVERSÕES
	
	strcpy(vec_strings[133], "i2l");
	strcpy(vec_strings[134], "i2f");
	strcpy(vec_strings[135], "i2d");
	strcpy(vec_strings[136], "l2i");
	strcpy(vec_strings[137], "l2f");
	strcpy(vec_strings[138], "l2d");
	strcpy(vec_strings[139], "f2i");
	strcpy(vec_strings[140], "f2l");
	strcpy(vec_strings[141], "f2d");
	strcpy(vec_strings[142], "d2i");
	strcpy(vec_strings[143], "d2l");
	strcpy(vec_strings[144], "d2f");
	strcpy(vec_strings[145], "i2b");
	strcpy(vec_strings[146], "i2c");
	strcpy(vec_strings[147], "i2s");
	
	//******************************************************************
	//COMPARAÇÕES
	
	strcpy(vec_strings[148], "lcmp");
	strcpy(vec_strings[149], "fcmpl");
	strcpy(vec_strings[150], "fcmpg");
	strcpy(vec_strings[151], "dcmpl");
	strcpy(vec_strings[152], "dcmpg");
	strcpy(vec_strings[153], "ifeq");
	strcpy(vec_strings[154], "ifne");
	strcpy(vec_strings[155], "iflt");
	strcpy(vec_strings[156], "ifge");
	strcpy(vec_strings[157], "ifgt");
	strcpy(vec_strings[158], "ifle");
	strcpy(vec_strings[159], "if_icmpeq");
	strcpy(vec_strings[160], "if_icmpne");
	strcpy(vec_strings[161], "if_icmplt");
	strcpy(vec_strings[162], "if_icmpge");
	strcpy(vec_strings[163], "if_icmpgt");
	strcpy(vec_strings[164], "if_icmple");
	strcpy(vec_strings[165], "if_acmpeq");
	strcpy(vec_strings[166], "if_acmpne");
	
	//******************************************************************
	//CONTROLE
	
	strcpy(vec_strings[167], "goto");
	strcpy(vec_strings[168], "jsr");
	strcpy(vec_strings[169], "ret");
	strcpy(vec_strings[170], "tableswitch");
	strcpy(vec_strings[171], "lookupswitch");
	strcpy(vec_strings[172], "ireturn");
	strcpy(vec_strings[173], "lreturn");
	strcpy(vec_strings[174], "freturn");
	strcpy(vec_strings[175], "dreturn");
	strcpy(vec_strings[176], "areturn");
	strcpy(vec_strings[177], "return");
	
	//******************************************************************
	//REFERÊNCIAS
	
	strcpy(vec_strings[178], "getstatic");
	strcpy(vec_strings[179], "putstatic");
	strcpy(vec_strings[180], "getfield");
	strcpy(vec_strings[181], "putfield");
	strcpy(vec_strings[182], "invokevirtual");
	strcpy(vec_strings[183], "invokespecial");
	strcpy(vec_strings[184], "invokestatic");
	strcpy(vec_strings[185], "invokeinterface");
	strcpy(vec_strings[186], "invokedynamic");
	strcpy(vec_strings[187], "new");
	strcpy(vec_strings[188], "newarray");
	strcpy(vec_strings[189], "anewarray");
	strcpy(vec_strings[190], "arraylength");
	strcpy(vec_strings[191], "athrow");
	strcpy(vec_strings[192], "checkcast");
	strcpy(vec_strings[193], "instanceof");
	strcpy(vec_strings[194], "monitorenter");
	strcpy(vec_strings[195], "monitorexit");
	
	//******************************************************************
	//EXTENDIDO
	
	strcpy(vec_strings[196], "wide");
	strcpy(vec_strings[197], "multianewarray");
	strcpy(vec_strings[198], "ifnull");
	strcpy(vec_strings[199], "ifnonnull");
	strcpy(vec_strings[200], "goto_w");
	strcpy(vec_strings[201], "jsr_w");
	
	//******************************************************************
	//CONSTANTES
	
  	instructions[0].ins = nop;		instructions[0].byte = 0;
  	instructions[1].ins = aconst_null;	instructions[1].byte = 0;
  	instructions[2].ins = iconst_m1;	instructions[2].byte = 0;
  	instructions[3].ins = iconst_0;		instructions[3].byte = 0;
  	instructions[4].ins = iconst_1;		instructions[4].byte = 0;
  	instructions[5].ins = iconst_2;		instructions[5].byte = 0;
	instructions[6].ins = iconst_3;		instructions[6].byte = 0;
  	instructions[7].ins = iconst_4;		instructions[7].byte = 0;
  	instructions[8].ins = iconst_5;		instructions[8].byte = 0;
  	instructions[9].ins = lconst_0;		instructions[9].byte = 0;
  	instructions[10].ins = lconst_1;	instructions[10].byte = 0;
  	instructions[11].ins = fconst_0;	instructions[11].byte = 0;
  	instructions[12].ins = fconst_1;	instructions[12].byte = 0;
  	instructions[13].ins = fconst_2;	instructions[13].byte = 0;
  	instructions[14].ins = dconst_0;	instructions[14].byte = 0;
  	instructions[15].ins = dconst_1;	instructions[15].byte = 0;
  	instructions[16].ins = bipush;		instructions[16].byte = 1;
  	instructions[17].ins = sipush;		instructions[17].byte = 2;
  	instructions[18].ins = ldc;		instructions[18].byte = 1;
  	instructions[19].ins = ldc_w;		instructions[19].byte = 2;
  	instructions[20].ins = ldc2_w;		instructions[20].byte = 2;
	
	//******************************************************************
	//LOADS
	
	instructions[21].ins = iload;		instructions[21].byte = 1;
	instructions[22].ins = lload;		instructions[22].byte = 1;
	instructions[23].ins = fload;		instructions[23].byte = 1;
	instructions[24].ins = dload;		instructions[24].byte = 1;
	instructions[25].ins = aload;		instructions[25].byte = 1;
	instructions[26].ins = iload_0;		instructions[26].byte = 0;
	instructions[27].ins = iload_1;		instructions[27].byte = 0;
	instructions[28].ins = iload_2;		instructions[28].byte = 0;
	instructions[29].ins = iload_3;		instructions[29].byte = 0;
	instructions[30].ins = lload_0;		instructions[30].byte = 0;
	instructions[31].ins = lload_1;		instructions[31].byte = 0;
	instructions[32].ins = lload_2;		instructions[32].byte = 0;
	instructions[33].ins = lload_3;		instructions[33].byte = 0;
	instructions[34].ins = fload_0;		instructions[34].byte = 0;
	instructions[35].ins = fload_1;		instructions[35].byte = 0;
	instructions[36].ins = fload_2;		instructions[36].byte = 0;
	instructions[37].ins = fload_3;		instructions[37].byte = 0;
	instructions[38].ins = dload_0;		instructions[38].byte = 0;
	instructions[39].ins = dload_1;		instructions[39].byte = 0;
	instructions[40].ins = dload_2;		instructions[40].byte = 0;
	instructions[41].ins = dload_3;		instructions[41].byte = 0;
	instructions[42].ins = aload_0;		instructions[42].byte = 0;
	instructions[43].ins = aload_1;		instructions[43].byte = 0;
	instructions[44].ins = aload_2;		instructions[44].byte = 0;
	instructions[45].ins = aload_3;		instructions[45].byte = 0;
	instructions[46].ins = iaload;		instructions[46].byte = 0;
	instructions[47].ins = laload;		instructions[47].byte = 0;
	instructions[48].ins = faload;		instructions[48].byte = 0;
	instructions[49].ins = daload;		instructions[49].byte = 0;
	instructions[50].ins = aaload;		instructions[50].byte = 0;
	instructions[51].ins = baload;		instructions[51].byte = 0;
	instructions[52].ins = caload;		instructions[52].byte = 0;
	instructions[53].ins = saload;		instructions[53].byte = 0;
	
	//******************************************************************
	//STORES
	
	instructions[54].ins = istore;		instructions[54].byte = 1;
	instructions[55].ins = lstore;		instructions[55].byte = 1;
	instructions[56].ins = fstore;		instructions[56].byte = 1;
	instructions[57].ins = dstore;		instructions[57].byte = 1;
	instructions[58].ins = astore;		instructions[58].byte = 1;
	instructions[59].ins = istore_0;	instructions[59].byte = 0;
	instructions[60].ins = istore_1;	instructions[60].byte = 0;
	instructions[61].ins = istore_2;	instructions[61].byte = 0;
	instructions[62].ins = istore_3;	instructions[62].byte = 0;
	instructions[63].ins = lstore_0;	instructions[63].byte = 0;
	instructions[64].ins = lstore_1;	instructions[64].byte = 0;
	instructions[65].ins = lstore_2;	instructions[65].byte = 0;
	instructions[66].ins = lstore_3;	instructions[66].byte = 0;
	instructions[67].ins = fstore_0;	instructions[67].byte = 0;
	instructions[68].ins = fstore_1;	instructions[68].byte = 0;
	instructions[69].ins = fstore_2;	instructions[69].byte = 0;
	instructions[70].ins = fstore_3;	instructions[70].byte = 0;
	instructions[71].ins = dstore_0;	instructions[71].byte = 0;
	instructions[72].ins = dstore_1;	instructions[72].byte = 0;
	instructions[73].ins = dstore_2;	instructions[73].byte = 0;
	instructions[74].ins = dstore_3;	instructions[74].byte = 0;
	instructions[75].ins = astore_0;	instructions[75].byte = 0;
	instructions[76].ins = astore_1;	instructions[76].byte = 0;
	instructions[77].ins = astore_2;	instructions[77].byte = 0;
	instructions[78].ins = astore_3;	instructions[78].byte = 0;
	instructions[79].ins = iastore;		instructions[79].byte = 0;
	instructions[80].ins = lastore;		instructions[80].byte = 0;
	instructions[81].ins = fastore;		instructions[81].byte = 0;
	instructions[82].ins = dastore;		instructions[82].byte = 0;
	instructions[83].ins = aastore;		instructions[83].byte = 0;
	instructions[84].ins = bastore;		instructions[84].byte = 0;
	instructions[85].ins = castore;		instructions[85].byte = 0;
	instructions[86].ins = sastore;		instructions[86].byte = 0;
	
	//******************************************************************
	//PILHA
	
// 	instructions[87].ins = pop;		instructions[87].byte = 0;
// 	instructions[88].ins = pop2;		instructions[88].byte = 0;
// 	instructions[89].ins = dup;		instructions[89].byte = 0;
// 	instructions[90].ins = dup_x1;		instructions[90].byte = 0;
// 	instructions[91].ins = dup_x2;		instructions[91].byte = 0;
// 	instructions[92].ins = dup2;		instructions[92].byte = 0;
// 	instructions[93].ins = dup2_x1;		instructions[93].byte = 0;
// 	instructions[94].ins = dup2_x2;		instructions[94].byte = 0;
// 	instructions[95].ins = swap;		instructions[95].byte = 0;
	
	//******************************************************************
	//OPERAÇÕES MATEMÁTICAS	
	
	instructions[96].ins = iadd;		instructions[96].byte = 0;
	instructions[97].ins = ladd;		instructions[97].byte = 0;
	instructions[98].ins = fadd;		instructions[98].byte = 0;
	instructions[99].ins = dadd;		instructions[99].byte = 0;
	instructions[100].ins = isub;		instructions[100].byte = 0;
	instructions[101].ins = lsub;		instructions[101].byte = 0;
	instructions[102].ins = fsub;		instructions[102].byte = 0;
	instructions[103].ins = dsub;		instructions[103].byte = 0;
	instructions[104].ins = imul;		instructions[104].byte = 0;
	instructions[105].ins = lmul;		instructions[105].byte = 0;
	instructions[106].ins = fmul;		instructions[106].byte = 0;
	instructions[107].ins = dmul;		instructions[107].byte = 0;
	instructions[108].ins = idiv;		instructions[108].byte = 0;
	instructions[109].ins = ldiv_;		instructions[109].byte = 0;
	instructions[110].ins = fdiv;		instructions[110].byte = 0;
	instructions[111].ins = ddiv;		instructions[111].byte = 0;
	instructions[112].ins = irem;		instructions[112].byte = 0;
	instructions[113].ins = lrem;		instructions[111].byte = 0;
	instructions[114].ins = frem;		instructions[114].byte = 0;
	instructions[115].ins = drem_;		instructions[115].byte = 0;
	instructions[116].ins = ineg;		instructions[116].byte = 0;
	instructions[117].ins = lneg;		instructions[117].byte = 0;
	instructions[118].ins = fneg;		instructions[118].byte = 0;
	instructions[119].ins = dneg;		instructions[119].byte = 0;
	instructions[120].ins = ishl;		instructions[120].byte = 0;
	instructions[121].ins = lshl;		instructions[121].byte = 0;
	instructions[122].ins = ishr;		instructions[122].byte = 0;
	instructions[123].ins = lshr;		instructions[123].byte = 0;
	instructions[124].ins = iushr;		instructions[124].byte = 0;
	instructions[125].ins = lushr;		instructions[125].byte = 0;
	instructions[126].ins = iand;		instructions[126].byte = 0;
	instructions[127].ins = land;		instructions[127].byte = 0;
	instructions[128].ins = ior;		instructions[128].byte = 0;
	instructions[129].ins = lor;		instructions[129].byte = 0;
	instructions[130].ins = ixor;		instructions[130].byte = 0;
	instructions[131].ins = lxor;		instructions[131].byte = 0;
	instructions[132].ins = iinc;		instructions[132].byte = 2;
	
	//******************************************************************
	//CONVERSÕES
	
	instructions[133].ins = i2l;		instructions[133].byte = 0;
	instructions[134].ins = i2f;		instructions[134].byte = 0;
	instructions[135].ins = i2d;		instructions[135].byte = 0;
	instructions[136].ins = l2i;		instructions[136].byte = 0;
	instructions[137].ins = l2f;		instructions[137].byte = 0;
	instructions[138].ins = l2d;		instructions[138].byte = 0;
	instructions[139].ins = f2i;		instructions[139].byte = 0;
	instructions[140].ins = f2l;		instructions[140].byte = 0;
	instructions[141].ins = f2d;		instructions[141].byte = 0;
	instructions[142].ins = d2i;		instructions[142].byte = 0;
	instructions[143].ins = d2l;		instructions[143].byte = 0;
	instructions[144].ins = d2f;		instructions[144].byte = 0;
	instructions[145].ins = i2b;		instructions[145].byte = 0;
	instructions[146].ins = i2c;		instructions[146].byte = 0;
	instructions[147].ins = i2s;		instructions[147].byte = 0;
	
	//******************************************************************
	//COMPARAÇÕES
		
	instructions[148].ins = lcmp;		instructions[148].byte = 0;
	instructions[149].ins = fcmpl;		instructions[149].byte = 0;
	instructions[150].ins = fcmpg;		instructions[148].byte = 0;
	instructions[151].ins = dcmpl;		instructions[151].byte = 0;
	instructions[152].ins = dcmpg;		instructions[152].byte = 0;
	instructions[153].ins = ifeq;		instructions[153].byte = 2;
	instructions[154].ins = ifne;		instructions[154].byte = 2;
	instructions[155].ins = iflt;		instructions[155].byte = 2;
	instructions[156].ins = ifge;		instructions[156].byte = 2;
	instructions[157].ins = ifgt;		instructions[157].byte = 2;
	instructions[158].ins = ifle;		instructions[158].byte = 2;
	instructions[159].ins = if_icmpeq;	instructions[159].byte = 2;
	instructions[160].ins = if_icmpne;	instructions[160].byte = 2;
	instructions[161].ins = if_icmplt;	instructions[161].byte = 2;
	instructions[162].ins = if_icmpge;	instructions[162].byte = 2;
	instructions[163].ins = if_icmpgt;	instructions[163].byte = 2;
	instructions[164].ins = if_icmple;	instructions[164].byte = 2;
	instructions[165].ins = if_acmpeq;	instructions[165].byte = 2;
	instructions[166].ins = if_acmpne;	instructions[166].byte = 2;
	
	//******************************************************************
	//CONTROLE
	
	instructions[167].ins = goto_;		instructions[167].byte = 2;
	instructions[168].ins = jsr;		instructions[168].byte = 2;
	instructions[169].ins = ret;		instructions[169].byte = 1;
	instructions[170].ins = tableswitch;	instructions[170].byte = 14; //CONFIRMAR
	instructions[171].ins = lookupswitch;	instructions[171].byte = 10; //CONFIRMAR
	instructions[172].ins = ireturn;	instructions[172].byte = 0;
	instructions[173].ins = lreturn;	instructions[173].byte = 0;
	instructions[174].ins = freturn;	instructions[174].byte = 0;
	instructions[175].ins = dreturn;	instructions[175].byte = 0;
	instructions[176].ins = areturn;	instructions[176].byte = 0;
	instructions[177].ins = return_;	instructions[177].byte = 0;
	
	//******************************************************************
	//REFERÊNCIAS
	
	instructions[178].ins = getstatic;	instructions[178].byte = 2;
	instructions[179].ins = putstatic;	instructions[179].byte = 2;
	instructions[180].ins = getfield;	instructions[180].byte = 2;
	instructions[181].ins = putfield;	instructions[181].byte = 2;
	instructions[182].ins = invokevirtual;	instructions[182].byte = 2;
	instructions[183].ins = invokespecial;	instructions[183].byte = 2;
	instructions[184].ins = invokestatic;	instructions[184].byte = 2;
	instructions[185].ins = invokeinterface;instructions[185].byte = 4;
// 	instructions[186].ins = invokedynamic;	instructions[186].byte = 4;
	instructions[187].ins = new;		instructions[187].byte = 2;
	instructions[188].ins = newarray;	instructions[188].byte = 1;
	instructions[189].ins = anewarray;	instructions[189].byte = 2;
	instructions[190].ins = arraylength;	instructions[190].byte = 0;
// 	instructions[191].ins = athrow;		instructions[191].byte = 0;
// 	instructions[192].ins = checkcast;	instructions[192].byte = 2;
// 	instructions[193].ins = instanceof;	instructions[193].byte = 2;
// 	instructions[194].ins = monitorenter;	instructions[194].byte = 0;
// 	instructions[195].ins = monitorexit;	instructions[195].byte = 0;
	
	//******************************************************************
	//EXTENDIDO
	
	instructions[196].ins = wide;		instructions[196].byte = 3; //PODE SER 5 TAMBÉM DEPENDENDO DO OPCODE, FAZER A EXCESSÃO DEPOIS
	instructions[197].ins = multianewarray;	instructions[197].byte = 3;
	instructions[198].ins = ifnull;		instructions[198].byte = 2;
	instructions[199].ins = ifnonnull;	instructions[199].byte = 2;
	instructions[200].ins = goto_w;		instructions[200].byte = 4;
	instructions[201].ins = jsr_w;		instructions[201].byte = 4;

 	for (int i=0; i < 202; i++){
  		instructions[i].hexa = i;
		strcpy(instructions[i].name, vec_strings[i]);
 	}
	
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

void inicializa_pilha(Node *pilha){
	
	//Inicializa a pilha com o primeiro elemento em NULL
	pilha->prox = NULL;
	
	//Define o tamanho da pilha em 0
	tamanho_pilha = 0;
}

Node *aloca_elemento(int32_t dado){
	
	//Cria um espaço na memória do tamanho de Node para a novo elemento "novo"
	Node *novo = (Node *) malloc(sizeof(Node));
	
	//Condicional pra caso não dê pra criar o "novo"
	if(!novo){
		printf("Sem memória disponivel!\n");
		exit(0);
	}else{
		novo->dado = dado;
		return novo;
	}
}

void empilha(Node *pilha, int32_t dado){
	
	Node *novo_elemento = aloca_elemento(dado);
	novo_elemento->prox = NULL;
	
	if(verifica_pilha_vazia(pilha))
		pilha->prox=novo_elemento;
	else{
		Node *tmp = pilha->prox;
		
		while(tmp->prox != NULL)
			tmp = tmp->prox;
		
		tmp->prox = novo_elemento;
	}
	
	tamanho_pilha++;
}

int32_t desempilha(Node *pilha){
	
	if(pilha->prox == NULL)
		printf("A pilha está vazia\n\n");
	else{
		Node *ultimo_elem = pilha->prox, *penultimo_elem = pilha;
		
		while(ultimo_elem->prox != NULL){
			penultimo_elem = ultimo_elem;
			ultimo_elem = ultimo_elem->prox;
		}
		
		penultimo_elem->prox = NULL;
		
		tamanho_pilha--;
		return ultimo_elem->dado;
	}
	return 0;
}

int verifica_pilha_vazia(Node *pilha){
	if(pilha->prox == NULL)
		return 1;
	else
		return 0;
}

void mostra_pilha(Node *pilha){
	
	if(verifica_pilha_vazia(pilha)){
		printf("Pilha vazia!\n\n");
		return ;
	}
	
	Node *ponteiro_tmp;
	ponteiro_tmp = pilha->prox;
	
	printf("\nPilha:");
	
	while(ponteiro_tmp != NULL){
   		printf("%5d", ponteiro_tmp->dado); //%5d => printa com 5 caracteres sempre
		ponteiro_tmp = ponteiro_tmp->prox;
	}
	
	printf("\n        ");
	
	for(int count=0; count<tamanho_pilha; count++)
  		printf("  ^  ");
	
	printf("\nOrdem:");
	
 	for(int count=0; count<tamanho_pilha; count++){
  		if (tamanho_pilha-1 != count)
  			printf("%5d", count+1);
 		else 
  			printf("   topo\n");
 	}

  	printf("\n");
  	free(ponteiro_tmp);
	
	return;
}

void zera_pilha(Node *pilha){
	if(!verifica_pilha_vazia(pilha)){
		Node *proxNode,
		*atual;

		atual = pilha->prox;
		while(atual != NULL){
			proxNode = atual->prox;
			free(atual);
			atual = proxNode;
		}
	}
	
	inicializa_pilha(pilha);
}

void destroi_pilha(Node *pilha){
	free(pilha);
}

void internal_error(){ printf("(-) InternalError\n"); exit(0);}

void out_of_mem(){ printf("(-) OutOfMemoryError\n"); exit(0);}

void stack__ovflw_error(){ printf("(-) StackOverflowError\n"); exit(0);}

void unkwn_err(){ printf("(-) UnknownError\n"); exit(0);}

void ArithmeticException(){printf("(-) ArithmeticException\n");}

//CONSTANTES
void nop(){
	pc++;
	return;
}

//PRECISA VER COMO FAZER PRA COLOCAR O NULL NO TOPO DA PILHA
void aconst_null(Node *pilha){
	empilha(pilha, 0);
	pc++;
	return;
}
void iconst_m1(Node *pilha){
	empilha(pilha, -1);
	pc++;
}
void iconst_0(Node *pilha){
 	empilha(pilha, 0);
	pc++;
//  	return;
}
void iconst_1(Node *pilha){
	empilha(pilha, 1);
	pc++;
// 	return;
}
void iconst_2(Node *pilha){
	empilha(pilha, 2);
	pc++;
// 	return;
}
void iconst_3(Node *pilha){
	empilha(pilha, 3);
	pc++;
}
void iconst_4(Node *pilha){
	empilha(pilha, 4);
	pc++;
// 	return;
}
void iconst_5(Node *pilha){
	empilha(pilha, 5);
	pc++;
// 	return;
}
void lconst_0(Node *pilha){
	
	//De acordo com a especificação: "A value of type long or type double occupies two consecutive local variables"
	int32_t double_alta_pilha = 0;
	int32_t double_baixa_pilha = 0;
	
	empilha(pilha, double_alta_pilha);
	empilha(pilha, double_baixa_pilha);
	
	pc++;
	
	return;
}
void lconst_1(Node *pilha){
	
	//De acordo com a especificação: "A value of type long or type double occupies two consecutive local variables"
	int32_t double_alta_pilha = 0;
	int32_t double_baixa_pilha = 0;
	
	double_baixa_pilha |= 0x00000001;
	
	empilha(pilha, double_alta_pilha);
	empilha(pilha, double_baixa_pilha);
	
	pc++;
	
	return;
}
void fconst_0(Node *pilha){
	
	//Float por padrão possui 32 bits
	float valor = 0.0;
	int32_t para_empilhar;
	
	/*
	 * memcpy(void *str1, const void *str2, size_t n);
	 * str1 é o valor de destino
	 * str2 é o valor fonte
	 * n é o número de bytes a serem copiados
	 */
	memcpy(&para_empilhar, &valor, sizeof(int32_t));
	
	empilha(pilha, para_empilhar);
	
	return;
}
void fconst_1(Node *pilha){
	
	//Float por padrão possui 32 bits
	float valor = 1.0;
	int32_t para_empilhar;
	
	/*
	 * memcpy(void *str1, const void *str2, size_t n);
	 * str1 é o valor de destino
	 * str2 é o valor fonte
	 * n é o número de bytes a serem copiados
	 */
	memcpy(&para_empilhar, &valor, sizeof(int32_t));
	
	empilha(pilha, para_empilhar);
	
	return;
}
void fconst_2(Node *pilha){
	
	//Float por padrão possui 32 bits
	float valor = 2.0;
	int32_t para_empilhar;
	
	/*
	 * memcpy(void *str1, const void *str2, size_t n);
	 * str1 é o valor de destino
	 * str2 é o valor fonte
	 * n é o número de bytes a serem copiados
	 */
	memcpy(&para_empilhar, &valor, sizeof(int32_t));
	
	empilha(pilha, para_empilhar);
	
	/*
	valor = 0;
	para_empilhar = 0;
	
	para_empilhar = desempilha(pilha);
	
	memcpy(&valor, &para_empilhar, sizeof(int32_t));*/
	
	return;
}
void dconst_0(Node *pilha){
	
	//De acordo com a especificação: "A value of type long or type double occupies two consecutive local variables"
	
	double valor1 = 0.0, valor2 = 0.0;
	
	empilha(pilha, valor1);
	empilha(pilha, valor2);
	
	return;
}
void dconst_1(Node *pilha){
	
	//De acordo com a especificação: "A value of type long or type double occupies two consecutive local variables"
	
	double valor1 = 0.0, valor2 = 1.0;
	
	empilha(pilha, (int32_t)valor1);
	empilha(pilha, (int32_t)valor2);
	
	return;
}
void bipush(Node *pilha, int32_t byte){
	
	int8_t converte_para_8bits = 0x00;
	
	converte_para_8bits |= byte;
	
	int32_t completa_bits = 0x00000000;
	
	completa_bits |= byte;
	
 	empilha(pilha, completa_bits);
	return;
}
void sipush(Node *pilha, uint32_t byte1, uint32_t byte2){
	
	uint8_t valor_convertido_byte1 = 0x00, valor_convertido_byte2 = 0x00;
	
	valor_convertido_byte1 |= byte1;
	valor_convertido_byte2 |= byte2;
	
	uint16_t valor = 0x0000;
	int32_t para_empilhar = 0x00000000;
	
	valor |= valor_convertido_byte1;
	valor <<= 8;
	valor |= valor_convertido_byte2;
	
	para_empilhar |= valor;
	
	empilha(pilha, para_empilhar);
	
	return;
}
void ldc(){return;} //IMPLEMENTAR - PRECISA DA CONSTANT POOL
void ldc_w(){return;} //IMPLEMENTAR - PRECISA DA CONSTANT POOL
void ldc2_w(){return;} //IMPLEMENTAR - PRECISA DA CONSTANT POOL

//LOADS
void iload(){return;} //IMPLEMENTAR - PEGA O VALOR DA VARIÁVEL LOCAL E COLOCA NA PILHA
void lload(){return;} 
void fload(){return;}
void dload(){return;}
void aload(){return;}
void iload_0(){return;}
void iload_1(){return;}
void iload_2(){return;}
void iload_3(){return;}
void lload_0(){return;}
void lload_1(){return;}
void lload_2(){return;}
void lload_3(){return;}
void fload_0(){return;}
void fload_1(){return;}
void fload_2(){return;}
void fload_3(){return;}
void dload_0(){return;}
void dload_1(){return;}
void dload_2(){return;}
void dload_3(){return;}
void aload_0(){return;}
void aload_1(){return;}
void aload_2(){return;}
void aload_3(){return;}
void iaload(){return;}
void laload(){return;}
void faload(){return;}
void daload(){return;}
void aaload(){return;}
void baload(){return;}
void caload(){return;}
void saload(){return;}

//STORES
void istore(){return;}
void lstore(){return;}
void fstore(){return;}
void dstore(){return;}
void astore(){return;}
void istore_0(){return;}
void istore_1(){return;}
void istore_2(){return;}
void istore_3(){return;}
void lstore_0(){return;}
void lstore_1(){return;}
void lstore_2(){return;}
void lstore_3(){return;}
void fstore_0(){return;}
void fstore_1(){return;}
void fstore_2(){return;}
void fstore_3(){return;}
void dstore_0(){return;}
void dstore_1(){return;}
void dstore_2(){return;}
void dstore_3(){return;}
void astore_0(){return;}
void astore_1(){return;}
void astore_2(){return;}
void astore_3(){return;}
void iastore(){return;}
void lastore(){return;}
void fastore(){return;}
void dastore(){return;}
void aastore(){return;}
void bastore(){return;}
void castore(){return;}
void sastore(){return;}

//OPERAÇÕES MATEMÁTICAS
void iadd(Node *pilha){
	
	int32_t valor1 = desempilha(pilha);
	int32_t valor2 = desempilha(pilha);
	
	int64_t resultado;
	
	resultado = (long long int) valor1 + (long long int) valor2;
	
//  	printf("%"PRId64"\n", resultado);
	
  	if (resultado > INT32_MAX){
		printf("\n(-) ERROR! ");
		printf("%s\n\n", strerror(34));
  	}
	
	empilha(pilha, (int32_t)resultado);
	
	return;
}
void ladd(Node *pilha){
	
	int64_t valor1_primeira_parte = desempilha(pilha);
	int64_t valor1_segunda_parte  = desempilha(pilha);
	int64_t valor2_primeira_parte = desempilha(pilha);
	int64_t valor2_segunda_parte  = desempilha(pilha);
	
	int64_t valor1, valor2;
	
	valor1 = 0x00000000FFFFFFFF & valor1_primeira_parte;
	valor1_segunda_parte <<= 32;
	valor1 |= valor1_segunda_parte;
	
	valor2 = 0x00000000FFFFFFFF & valor2_primeira_parte;
	valor2_segunda_parte <<= 32;
	valor2 |= valor2_segunda_parte;
	
	int64_t resultado = valor1 + valor2;
// 	printf("\nHEXA = %016p\n", resultado);
	
  	if (valor1 > (LLONG_MAX - valor2)){
		printf("\n(-) ERROR! ");
		printf("%s\n\n", strerror(34));
  	}
	
	/*
	 * Empilhar o maior valor
	 * FFFFFFFF FFFFFFFF (64 bits)
	 * 00000000 FFFFFFFF (Shift de 32 pra direita)
	 * 00000000 FFFFFFFF & FFFFFFFF = FFFFFFFF (Resultado de 32 bits)
	 * 
	 * Empilhar o menor valor
	 * FFFFFFFF FFFFFFFF (64 bits)
	 * FFFFFFFF 00000000 (Shift de 32 pra esquerda)
	 * 00000000 FFFFFFFF (Shift de 32 pra direita)
	 * 00000000 FFFFFFFF & FFFFFFFF = FFFFFFFF (Resultado de 32 bits)
	 */
	
	int32_t maior_valor = 0xFFFFFFFF;
	maior_valor &= (resultado >> 32);
	
	int32_t menor_valor = 0xFFFFFFFF;
	int64_t aux = (resultado << 32);
	menor_valor &= (aux >> 32);
	
 	empilha(pilha, maior_valor);
 	empilha(pilha, menor_valor);
	
	return;
}
void fadd(Node *pilha){
	
   	int32_t valor1 = desempilha(pilha);
   	int32_t valor2 = desempilha(pilha);
	int32_t para_empilhar;
	
	float valor1_f, valor2_f;
	
	float valor_float;
	
	/*
	 * memcpy(void *str1, const void *str2, size_t n);
	 * str1 é o valor de destino
	 * str2 é o valor fonte
	 * n é o número de bytes a serem copiados
	 */
	memcpy(&valor1_f, &valor1, sizeof(int32_t));
	memcpy(&valor2_f, &valor2, sizeof(int32_t));
	
	if (valor1_f == NAN || valor2_f == NAN)
		valor_float = NAN;
	else {
		if ((valor1_f == INFINITY && valor2_f == -INFINITY) || (valor1_f == -INFINITY && valor2_f == INFINITY))
			valor_float = NAN;
		else {
			if (valor1_f == INFINITY && valor2_f == INFINITY)
				valor_float = INFINITY;
			else {
				if (valor1_f == -INFINITY && valor2_f == -INFINITY)
					valor_float = -INFINITY;
				else{
					if ((valor1_f == INFINITY && valor2_f != INFINITY && valor2_f != -INFINITY) || (valor2_f == INFINITY && valor1_f != INFINITY && valor1_f != -INFINITY))
						valor_float = INFINITY;
					else {
						if ((valor1_f == -INFINITY && valor2_f != INFINITY && valor2_f != -INFINITY) || (valor2_f == -INFINITY && valor1_f != INFINITY && valor1_f != -INFINITY))
							valor_float = INFINITY;
						else {
							if ((valor1_f == -0 && valor2_f == 0) || (valor1_f == 0 && valor2_f == -0))
								valor_float = 0.0;
							else {
								if (valor1_f == 0 && valor2_f == 0)
									valor_float = 0.0;
								else {
									if (valor1_f == -0 && valor2_f == -0){
										valor_float = -0.0;
									}
									else {
										valor_float = valor1_f+valor2_f;
									}
								}
							}
						}
					}
				}
			}
		}
	}
	
	memcpy(&para_empilhar, &valor_float, sizeof(int32_t));
	
	empilha(pilha, para_empilhar);
	
	return;
}
void dadd(Node *pilha){
	
	int64_t valor1_lo = desempilha(pilha);
	int64_t valor1_hi = desempilha(pilha);
   	int64_t valor2_lo = desempilha(pilha);
	int64_t valor2_hi = desempilha(pilha);
	int32_t para_empilhar_lo = 0xFFFFFFFF;
	int32_t para_empilhar_hi = 0xFFFFFFFF;
	int64_t para_empilhar;
	int64_t valor1, valor2;
	
	double valor1_f, valor2_f;
	double valor_float;
	
	valor1 = 0x00000000FFFFFFFF & valor1_lo;
	valor1_hi <<= 32;
	valor1 |= valor1_hi;
	
	valor2 = 0x00000000FFFFFFFF & valor2_lo;
	valor2_hi <<= 32;
	valor2 |= valor2_hi;
	
	/*
	 * memcpy(void *str1, const void *str2, size_t n);
	 * str1 é o valor de destino
	 * str2 é o valor fonte
	 * n é o número de bytes a serem copiados
	 */
	memcpy(&valor1_f, &valor1, sizeof(double));
	memcpy(&valor2_f, &valor2, sizeof(double));
	
	if (valor1_f == NAN || valor2_f == NAN)
		valor_float = NAN;
	else {
		if ((valor1_f == INFINITY && valor2_f == -INFINITY) || (valor1_f == -INFINITY && valor2_f == INFINITY))
			valor_float = NAN;
		else {
			if (valor1_f == INFINITY && valor2_f == INFINITY)
				valor_float = INFINITY;
			else {
				if (valor1_f == -INFINITY && valor2_f == -INFINITY)
					valor_float = -INFINITY;
				else{
					if ((valor1_f == INFINITY && valor2_f != INFINITY && valor2_f != -INFINITY) || (valor2_f == INFINITY && valor1_f != INFINITY && valor1_f != -INFINITY))
						valor_float = INFINITY;
					else {
						if ((valor1_f == -INFINITY && valor2_f != INFINITY && valor2_f != -INFINITY) || (valor2_f == -INFINITY && valor1_f != INFINITY && valor1_f != -INFINITY))
							valor_float = INFINITY;
						else {
							if ((valor1_f == -0 && valor2_f == 0) || (valor1_f == 0 && valor2_f == -0))
								valor_float = 0.0;
							else {
								if (valor1_f == 0 && valor2_f == 0)
									valor_float = 0.0;
								else {
									if (valor1_f == -0 && valor2_f == -0){
										valor_float = -0.0;
									}
									else {
										valor_float = valor1_f+valor2_f;
									}
								}
							}
						}
					}
				}
			}
		}
	}
	
	memcpy(&para_empilhar, &valor_float, sizeof(int64_t));
	para_empilhar_hi &= para_empilhar >> 32;
	para_empilhar_lo &= para_empilhar;
	
	empilha(pilha, para_empilhar_hi);
	empilha(pilha, para_empilhar_lo);
	
	return;
}
void isub(Node *pilha){
	
	int32_t valor1 = desempilha(pilha);
	int32_t valor2 = desempilha(pilha);
	
	int64_t resultado;
	
	resultado = (long long int) valor1 - (long long int) valor2;
	
//  	printf("%"PRId64"\n", resultado);
	
  	if (resultado < INT32_MIN){
		printf("\n(-) ERROR! ");
		printf("%s\n\n", strerror(34));
  	}
	
	empilha(pilha, (int32_t)resultado);
	
	return;
}
void lsub(Node *pilha){
	int64_t valor1_primeira_parte = desempilha(pilha);
	int64_t valor1_segunda_parte  = desempilha(pilha);
	int64_t valor2_primeira_parte = desempilha(pilha);
	int64_t valor2_segunda_parte  = desempilha(pilha);
	
	int64_t valor1, valor2;
	
	valor1 = 0x00000000FFFFFFFF & valor1_primeira_parte;
	valor1_segunda_parte <<= 32;
	valor1 |= valor1_segunda_parte;
	
	valor2 = 0x00000000FFFFFFFF & valor2_primeira_parte;
	valor2_segunda_parte <<= 32;
	valor2 |= valor2_segunda_parte;
	
	int64_t resultado = valor1 - valor2;
// 	printf("\nHEXA = %016p\n", resultado);
	
  	if (valor1 < (LLONG_MIN - valor2)){
		printf("\n(-) ERROR! ");
		printf("%s\n\n", strerror(34));
  	}
	
	/*
	 * Empilhar o maior valor
	 * FFFFFFFF FFFFFFFF (64 bits)
	 * 00000000 FFFFFFFF (Shift de 32 pra direita)
	 * 00000000 FFFFFFFF & FFFFFFFF = FFFFFFFF (Resultado de 32 bits)
	 * 
	 * Empilhar o menor valor
	 * FFFFFFFF FFFFFFFF (64 bits)
	 * FFFFFFFF 00000000 (Shift de 32 pra esquerda)
	 * 00000000 FFFFFFFF (Shift de 32 pra direita)
	 * 00000000 FFFFFFFF & FFFFFFFF = FFFFFFFF (Resultado de 32 bits)
	 */
	
	int32_t maior_valor = 0xFFFFFFFF;
	maior_valor &= (resultado >> 32);
	
	int32_t menor_valor = 0xFFFFFFFF;
	int64_t aux = (resultado << 32);
	menor_valor &= (aux >> 32);
	
 	empilha(pilha, maior_valor);
 	empilha(pilha, menor_valor);
	
	return;
}
void fsub(Node *pilha){
	
	int32_t valor1 = desempilha(pilha);
   	int32_t valor2 = desempilha(pilha);
	int32_t para_empilhar;
	
	float valor1_f, valor2_f;
	
	float valor_float;
	
	/*
	 * memcpy(void *str1, const void *str2, size_t n);
	 * str1 é o valor de destino
	 * str2 é o valor fonte
	 * n é o número de bytes a serem copiados
	 */
	memcpy(&valor1_f, &valor1, sizeof(int32_t));
	memcpy(&valor2_f, &valor2, sizeof(int32_t));
	
	if ((valor1 == -0.0 && valor2 == -0.0) || (valor1 == -0.0 && valor2 == 0.0))
		valor_float = -0.0;
	else{
		if ((valor1 == 0.0 && valor2 == -0.0) || (valor1 == 0.0 && valor2 == 0.0))
			valor_float = 0.0;
		else{
			valor_float = valor1_f-valor2_f;
		}
	}
	
	
	memcpy(&para_empilhar, &valor_float, sizeof(int32_t));
	
	empilha(pilha, para_empilhar);
	
	return;
}
void dsub(Node *pilha){
	
	int64_t valor1_lo = desempilha(pilha);
	int64_t valor1_hi = desempilha(pilha);
   	int64_t valor2_lo = desempilha(pilha);
	int64_t valor2_hi = desempilha(pilha);
	int32_t para_empilhar_lo = 0xFFFFFFFF;
	int32_t para_empilhar_hi = 0xFFFFFFFF;
	int64_t para_empilhar;
	int64_t valor1, valor2;
	
	double valor1_f, valor2_f;
	double valor_float;
	
	valor1 = 0x00000000FFFFFFFF & valor1_lo;
	valor1_hi <<= 32;
	valor1 |= valor1_hi;
	
	valor2 = 0x00000000FFFFFFFF & valor2_lo;
	valor2_hi <<= 32;
	valor2 |= valor2_hi;
	
	/*
	 * memcpy(void *str1, const void *str2, size_t n);
	 * str1 é o valor de destino
	 * str2 é o valor fonte
	 * n é o número de bytes a serem copiados
	 */
	memcpy(&valor1_f, &valor1, sizeof(double));
	memcpy(&valor2_f, &valor2, sizeof(double));
	
	if ((valor1 == -0.0 && valor2 == -0.0) || (valor1 == -0.0 && valor2 == 0.0))
		valor_float = -0.0;
	else{
		if ((valor1 == 0.0 && valor2 == -0.0) || (valor1 == 0.0 && valor2 == 0.0))
			valor_float = 0.0;
		else{
			valor_float = valor1_f-valor2_f;
		}
	}
	
	memcpy(&para_empilhar, &valor_float, sizeof(int64_t));
	para_empilhar_hi &= para_empilhar >> 32;
	para_empilhar_lo &= para_empilhar;
	
	empilha(pilha, para_empilhar_hi);
	empilha(pilha, para_empilhar_lo);
	
	return;
}
void imul(Node *pilha){
	
	int32_t valor1 = desempilha(pilha);
	int32_t valor2 = desempilha(pilha);
	
	int64_t resultado;
	
	resultado = (long long int) valor1 * (long long int) valor2;
	
//  	printf("%"PRId64"\n", resultado);
	
  	if (resultado > INT32_MAX){
		printf("\n(-) ERROR! ");
		printf("%s\n\n", strerror(34));
  	}
	
	empilha(pilha, (int32_t)resultado);
	
	return;
}
void lmul(Node *pilha){
	
	int64_t valor1_primeira_parte = desempilha(pilha);
	int64_t valor1_segunda_parte  = desempilha(pilha);
	int64_t valor2_primeira_parte = desempilha(pilha);
	int64_t valor2_segunda_parte  = desempilha(pilha);
	
	int64_t valor1, valor2;
	
	valor1 = 0x00000000FFFFFFFF & valor1_primeira_parte;
	valor1_segunda_parte <<= 32;
	valor1 |= valor1_segunda_parte;
	
	valor2 = 0x00000000FFFFFFFF & valor2_primeira_parte;
	valor2_segunda_parte <<= 32;
	valor2 |= valor2_segunda_parte;
	
	int64_t resultado = valor1 * valor2;
// 	printf("\nHEXA = %016p\n", resultado);
	
  	if (valor1 > (LLONG_MAX - valor2)){
		printf("\n(-) ERROR! ");
		printf("%s\n\n", strerror(34));
  	}
	
	/*
	 * Empilhar o maior valor
	 * FFFFFFFF FFFFFFFF (64 bits)
	 * 00000000 FFFFFFFF (Shift de 32 pra direita)
	 * 00000000 FFFFFFFF & FFFFFFFF = FFFFFFFF (Resultado de 32 bits)
	 * 
	 * Empilhar o menor valor
	 * FFFFFFFF FFFFFFFF (64 bits)
	 * FFFFFFFF 00000000 (Shift de 32 pra esquerda)
	 * 00000000 FFFFFFFF (Shift de 32 pra direita)
	 * 00000000 FFFFFFFF & FFFFFFFF = FFFFFFFF (Resultado de 32 bits)
	 */
	
	int32_t maior_valor = 0xFFFFFFFF;
	maior_valor &= (resultado >> 32);
	
	int32_t menor_valor = 0xFFFFFFFF;
	int64_t aux = (resultado << 32);
	menor_valor &= (aux >> 32);
	
 	empilha(pilha, maior_valor);
 	empilha(pilha, menor_valor);
	
	return;
}
void fmul(Node *pilha){
	
	int32_t valor1 = desempilha(pilha);
   	int32_t valor2 = desempilha(pilha);
	int32_t para_empilhar;
	
	float valor1_f, valor2_f;
	
	float valor_float;
	
	/*
	 * memcpy(void *str1, const void *str2, size_t n);
	 * str1 é o valor de destino
	 * str2 é o valor fonte
	 * n é o número de bytes a serem copiados
	 */
	memcpy(&valor1_f, &valor1, sizeof(int32_t));
	memcpy(&valor2_f, &valor2, sizeof(int32_t));
	
	if (valor1_f == NAN || valor2_f == NAN)
		valor_float = NAN;
	else {
		if ((valor1_f == INFINITY && valor2_f == -INFINITY) || (valor1_f == -INFINITY && valor2_f == INFINITY))
			valor_float = NAN;
		else {
			if (valor1_f == INFINITY && valor2_f == INFINITY)
				valor_float = INFINITY;
			else {
				if (valor1_f == -INFINITY && valor2_f == -INFINITY)
					valor_float = -INFINITY;
				else{
					if ((valor1_f == INFINITY && valor2_f != INFINITY && valor2_f != -INFINITY) || (valor2_f == INFINITY && valor1_f != INFINITY && valor1_f != -INFINITY))
						valor_float = INFINITY;
					else {
						if ((valor1_f == -INFINITY && valor2_f != INFINITY && valor2_f != -INFINITY) || (valor2_f == -INFINITY && valor1_f != INFINITY && valor1_f != -INFINITY))
							valor_float = INFINITY;
						else {
							if ((valor1_f == -0 && valor2_f == 0) || (valor1_f == 0 && valor2_f == -0))
								valor_float = 0.0;
							else {
								if (valor1_f == 0 && valor2_f == 0)
									valor_float = 0.0;
								else {
									if (valor1_f == -0 && valor2_f == -0){
										valor_float = -0.0;
									}
									else {
										valor_float = valor1_f*valor2_f;
									}
								}
							}
						}
					}
				}
			}
		}
	}
	
	memcpy(&para_empilhar, &valor_float, sizeof(int32_t));
	
	empilha(pilha, para_empilhar);
	
	return;
}
void dmul(Node *pilha){
	
	int64_t valor1_lo = desempilha(pilha);
	int64_t valor1_hi = desempilha(pilha);
   	int64_t valor2_lo = desempilha(pilha);
	int64_t valor2_hi = desempilha(pilha);
	int32_t para_empilhar_lo = 0xFFFFFFFF;
	int32_t para_empilhar_hi = 0xFFFFFFFF;
	int64_t para_empilhar;
	int64_t valor1, valor2;
	
	double valor1_f, valor2_f;
	double valor_float;
	
	valor1 = 0x00000000FFFFFFFF & valor1_lo;
	valor1_hi <<= 32;
	valor1 |= valor1_hi;
	
	valor2 = 0x00000000FFFFFFFF & valor2_lo;
	valor2_hi <<= 32;
	valor2 |= valor2_hi;
	
	/*
	 * memcpy(void *str1, const void *str2, size_t n);
	 * str1 é o valor de destino
	 * str2 é o valor fonte
	 * n é o número de bytes a serem copiados
	 */
	memcpy(&valor1_f, &valor1, sizeof(double));
	memcpy(&valor2_f, &valor2, sizeof(double));
	
	if (valor1_f == NAN || valor2_f == NAN)
		valor_float = NAN;
	else {
		if ((valor1_f == INFINITY && valor2_f == -INFINITY) || (valor1_f == -INFINITY && valor2_f == INFINITY))
			valor_float = NAN;
		else {
			if (valor1_f == INFINITY && valor2_f == INFINITY)
				valor_float = INFINITY;
			else {
				if (valor1_f == -INFINITY && valor2_f == -INFINITY)
					valor_float = -INFINITY;
				else{
					if ((valor1_f == INFINITY && valor2_f != INFINITY && valor2_f != -INFINITY) || (valor2_f == INFINITY && valor1_f != INFINITY && valor1_f != -INFINITY))
						valor_float = INFINITY;
					else {
						if ((valor1_f == -INFINITY && valor2_f != INFINITY && valor2_f != -INFINITY) || (valor2_f == -INFINITY && valor1_f != INFINITY && valor1_f != -INFINITY))
							valor_float = INFINITY;
						else {
							if ((valor1_f == -0 && valor2_f == 0) || (valor1_f == 0 && valor2_f == -0))
								valor_float = 0.0;
							else {
								if (valor1_f == 0 && valor2_f == 0)
									valor_float = 0.0;
								else {
									if (valor1_f == -0 && valor2_f == -0){
										valor_float = -0.0;
									}
									else {
										valor_float = valor1_f*valor2_f;
									}
								}
							}
						}
					}
				}
			}
		}
	}
	
	memcpy(&para_empilhar, &valor_float, sizeof(int64_t));
	para_empilhar_hi &= para_empilhar >> 32;
	para_empilhar_lo &= para_empilhar;
	
	empilha(pilha, para_empilhar_hi);
	empilha(pilha, para_empilhar_lo);
	
	return;
}
void idiv(Node *pilha){
	
	int32_t valor1 = desempilha(pilha);
	int32_t valor2 = desempilha(pilha);
	
	int64_t resultado;
	
	if (valor2 == 0)
		ArithmeticException();
	
	resultado = (long long int) valor1 / (long long int) valor2;
	
//  	printf("%"PRId64"\n", resultado);
	
  	if (resultado < INT32_MIN){
		printf("\n(-) ERROR! ");
		printf("%s\n\n", strerror(34));
  	}
	
	empilha(pilha, (int32_t)resultado);
	
	return;
}
void ldiv_(Node *pilha){
	
	int64_t valor1_primeira_parte = desempilha(pilha);
	int64_t valor1_segunda_parte  = desempilha(pilha);
	int64_t valor2_primeira_parte = desempilha(pilha);
	int64_t valor2_segunda_parte  = desempilha(pilha);
	
	int64_t valor1, valor2;
	
	valor1 = 0x00000000FFFFFFFF & valor1_primeira_parte;
	valor1_segunda_parte <<= 32;
	valor1 |= valor1_segunda_parte;
	
	valor2 = 0x00000000FFFFFFFF & valor2_primeira_parte;
	valor2_segunda_parte <<= 32;
	valor2 |= valor2_segunda_parte;
	
	int64_t resultado = valor1 / valor2;
// 	printf("\nHEXA = %016p\n", resultado);
	
	if (valor2 == 0)
		ArithmeticException();
	
  	if (valor1 > (LLONG_MAX - valor2)){
		printf("\n(-) ERROR! ");
		printf("%s\n\n", strerror(34));
  	}
	
	/*
	 * Empilhar o maior valor
	 * FFFFFFFF FFFFFFFF (64 bits)
	 * 00000000 FFFFFFFF (Shift de 32 pra direita)
	 * 00000000 FFFFFFFF & FFFFFFFF = FFFFFFFF (Resultado de 32 bits)
	 * 
	 * Empilhar o menor valor
	 * FFFFFFFF FFFFFFFF (64 bits)
	 * FFFFFFFF 00000000 (Shift de 32 pra esquerda)
	 * 00000000 FFFFFFFF (Shift de 32 pra direita)
	 * 00000000 FFFFFFFF & FFFFFFFF = FFFFFFFF (Resultado de 32 bits)
	 */
	
	int32_t maior_valor = 0xFFFFFFFF;
	maior_valor &= (resultado >> 32);
	
	int32_t menor_valor = 0xFFFFFFFF;
	int64_t aux = (resultado << 32);
	menor_valor &= (aux >> 32);
	
 	empilha(pilha, maior_valor);
 	empilha(pilha, menor_valor);
	
	return;
}
void fdiv(Node *pilha){
	
	int32_t valor1 = desempilha(pilha);
   	int32_t valor2 = desempilha(pilha);
	int32_t para_empilhar;
	
	float valor1_f, valor2_f;
	
	float valor_float;
	
	/*
	 * memcpy(void *str1, const void *str2, size_t n);
	 * str1 é o valor de destino
	 * str2 é o valor fonte
	 * n é o número de bytes a serem copiados
	 */
	memcpy(&valor1_f, &valor1, sizeof(int32_t));
	memcpy(&valor2_f, &valor2, sizeof(int32_t));
	
	if (valor1_f == NAN || valor2_f == NAN)
		valor_float = NAN;
	else {
		if ((valor1_f == INFINITY && valor2_f == -INFINITY) || (valor1_f == -INFINITY && valor2_f == INFINITY))
			valor_float = NAN;
		else {
			if (valor1_f == INFINITY && valor2_f == INFINITY)
				valor_float = INFINITY;
			else {
				if (valor1_f == -INFINITY && valor2_f == -INFINITY)
					valor_float = -INFINITY;
				else{
					if ((valor1_f == INFINITY && valor2_f != INFINITY && valor2_f != -INFINITY) || (valor2_f == INFINITY && valor1_f != INFINITY && valor1_f != -INFINITY))
						valor_float = INFINITY;
					else {
						if (valor1_f == 0 && valor2_f == 0)
							valor_float = NAN;
						else {
							if (valor2 == 0)
								valor_float = INFINITY;
							else {
								valor_float = valor1_f/valor2_f;
							}
						}
					}
				}
			}
		}
	}
	
	memcpy(&para_empilhar, &valor_float, sizeof(int32_t));
	
	empilha(pilha, para_empilhar);
	
	return;
}
void ddiv(Node *pilha){
	
	int64_t valor1_lo = desempilha(pilha);
	int64_t valor1_hi = desempilha(pilha);
   	int64_t valor2_lo = desempilha(pilha);
	int64_t valor2_hi = desempilha(pilha);
	int32_t para_empilhar_lo = 0xFFFFFFFF;
	int32_t para_empilhar_hi = 0xFFFFFFFF;
	int64_t para_empilhar;
	int64_t valor1, valor2;
	
	double valor1_f, valor2_f;
	double valor_float;
	
	valor1 = 0x00000000FFFFFFFF & valor1_lo;
	valor1_hi <<= 32;
	valor1 |= valor1_hi;
	
	valor2 = 0x00000000FFFFFFFF & valor2_lo;
	valor2_hi <<= 32;
	valor2 |= valor2_hi;
	
	/*
	 * memcpy(void *str1, const void *str2, size_t n);
	 * str1 é o valor de destino
	 * str2 é o valor fonte
	 * n é o número de bytes a serem copiados
	 */
	memcpy(&valor1_f, &valor1, sizeof(double));
	memcpy(&valor2_f, &valor2, sizeof(double));
	
	if (valor1_f == NAN || valor2_f == NAN)
		valor_float = NAN;
	else {
		if ((valor1_f == INFINITY && valor2_f == -INFINITY) || (valor1_f == -INFINITY && valor2_f == INFINITY))
			valor_float = NAN;
		else {
			if (valor1_f == INFINITY && valor2_f == INFINITY)
				valor_float = INFINITY;
			else {
				if (valor1_f == -INFINITY && valor2_f == -INFINITY)
					valor_float = -INFINITY;
				else{
					if ((valor1_f == INFINITY && valor2_f != INFINITY && valor2_f != -INFINITY) || (valor2_f == INFINITY && valor1_f != INFINITY && valor1_f != -INFINITY))
						valor_float = INFINITY;
					else {
						if (valor1_f == 0 && valor2_f == 0)
							valor_float = NAN;
						else {
							if (valor2 == 0)
								valor_float = INFINITY;
							else {
								valor_float = valor1_f/valor2_f;
							}
						}
					}
				}
			}
		}
	}
	
	memcpy(&para_empilhar, &valor_float, sizeof(int64_t));
	para_empilhar_hi &= para_empilhar >> 32;
	para_empilhar_lo &= para_empilhar;
	
	empilha(pilha, para_empilhar_hi);
	empilha(pilha, para_empilhar_lo);
	
	return;
}
void irem(Node *pilha){
	
	int32_t valor1 = desempilha(pilha);
	int32_t valor2 = desempilha(pilha);
	int32_t resultado;
	
	resultado = valor1%valor2;
	
	if (valor2 == 0)
		ArithmeticException();
	
	empilha(pilha, resultado);
	
	return;
}
void lrem(Node *pilha){
	
	int64_t valor1_primeira_parte = desempilha(pilha);
	int64_t valor1_segunda_parte  = desempilha(pilha);
	int64_t valor2_primeira_parte = desempilha(pilha);
	int64_t valor2_segunda_parte  = desempilha(pilha);
	
	int64_t valor1, valor2;
	
	valor1 = 0x00000000FFFFFFFF & valor1_primeira_parte;
	valor1_segunda_parte <<= 32;
	valor1 |= valor1_segunda_parte;
	
	valor2 = 0x00000000FFFFFFFF & valor2_primeira_parte;
	valor2_segunda_parte <<= 32;
	valor2 |= valor2_segunda_parte;
	
	int64_t resultado = valor1%valor2;
	
	if (valor2 == 0)
		ArithmeticException();
	
	int32_t maior_valor = 0xFFFFFFFF;
	maior_valor &= (resultado >> 32);
	
	int32_t menor_valor = 0xFFFFFFFF;
	int64_t aux = (resultado << 32);
	menor_valor &= (aux >> 32);
	
 	empilha(pilha, maior_valor);
 	empilha(pilha, menor_valor);
	
	return;
}
void frem(Node *pilha){
	
	int32_t valor1 = desempilha(pilha);
   	int32_t valor2 = desempilha(pilha);
	int32_t para_empilhar;
	
	float valor1_f, valor2_f;
	
	float valor_float;
	
	/*
	 * memcpy(void *str1, const void *str2, size_t n);
	 * str1 é o valor de destino
	 * str2 é o valor fonte
	 * n é o número de bytes a serem copiados
	 */
	memcpy(&valor1_f, &valor1, sizeof(int32_t));
	memcpy(&valor2_f, &valor2, sizeof(int32_t));
	
	if (valor1_f == NAN || valor2_f == NAN)
		valor_float = NAN;
	else {
		if (valor1 == INFINITY || valor2 == 0)
			valor_float = NAN;
		else {
			if (valor2 == INFINITY)
				valor_float = valor1;
			else {
				if (valor1 == 0)
					valor_float = valor1;
				else{
					valor_float = valor1%valor2;
				}
			}
		}
	}
	
	memcpy(&para_empilhar, &valor_float, sizeof(int32_t));
	
	empilha(pilha, para_empilhar);
	
	return;
}
void drem_(Node *pilha){
	
	int64_t valor1_lo = desempilha(pilha);
	int64_t valor1_hi = desempilha(pilha);
   	int64_t valor2_lo = desempilha(pilha);
	int64_t valor2_hi = desempilha(pilha);
	int32_t para_empilhar_lo = 0xFFFFFFFF;
	int32_t para_empilhar_hi = 0xFFFFFFFF;
	int64_t para_empilhar;
	int64_t valor1, valor2;
	
	double valor1_f, valor2_f;
	double valor_float;
	
	valor1 = 0x00000000FFFFFFFF & valor1_lo;
	valor1_hi <<= 32;
	valor1 |= valor1_hi;
	
	valor2 = 0x00000000FFFFFFFF & valor2_lo;
	valor2_hi <<= 32;
	valor2 |= valor2_hi;
	
	/*
	 * memcpy(void *str1, const void *str2, size_t n);
	 * str1 é o valor de destino
	 * str2 é o valor fonte
	 * n é o número de bytes a serem copiados
	 */
	memcpy(&valor1_f, &valor1, sizeof(double));
	memcpy(&valor2_f, &valor2, sizeof(double));
	
	if (valor1_f == NAN || valor2_f == NAN)
		valor_float = NAN;
	else {
		if (valor1 == INFINITY || valor2 == 0)
			valor_float = NAN;
		else {
			if (valor2 == INFINITY)
				valor_float = valor1;
			else {
				if (valor1 == 0)
					valor_float = valor1;
				else{
					valor_float = valor1%valor2;
				}
			}
		}
	}
	
	memcpy(&para_empilhar, &valor_float, sizeof(int64_t));
	para_empilhar_hi &= para_empilhar >> 32;
	para_empilhar_lo &= para_empilhar;
	
	empilha(pilha, para_empilhar_hi);
	empilha(pilha, para_empilhar_lo);
	
	return;
}
void ineg(Node *pilha){return;}
void lneg(Node *pilha){return;}
void fneg(Node *pilha){return;}
void dneg(Node *pilha){return;}
void ishl(Node *pilha){return;}
void lshl(Node *pilha){return;}
void ishr(Node *pilha){return;}
void lshr(Node *pilha){return;}
void iushr(Node *pilha){return;}
void lushr(Node *pilha){return;}
void iand(Node *pilha){return;}
void land(Node *pilha){return;}
void ior(Node *pilha){return;}
void lor(Node *pilha){return;}
void ixor(Node *pilha){return;}
void lxor(Node *pilha){return;}
void iinc(Node *pilha){return;}

//CONVERSÕES
void i2l(){return;}
void i2f(){return;}
void i2d(){return;}
void l2i(){return;}
void l2f(){return;}
void l2d(){return;}
void f2i(){return;}
void f2l(){return;}
void f2d(){return;}
void d2i(){return;}
void d2l(){return;}
void d2f(){return;}
void i2b(){return;}
void i2c(){return;}
void i2s(){return;}

//COMPARAÇÕES
void lcmp(){return;}
void fcmpl(){return;}
void fcmpg(){return;}
void dcmpl(){return;}
void dcmpg(){return;}
void ifeq(){return;}
void ifne(){return;}
void iflt(){return;}
void ifge(){return;}
void ifgt(){return;}
void ifle(){return;}
void if_icmpeq(){return;}
void if_icmpne(){return;}
void if_icmplt(){return;}
void if_icmpge(){return;}
void if_icmpgt(){return;}
void if_icmple(){return;}
void if_acmpeq(){return;}
void if_acmpne(){return;}

//CONTROLES
void goto_(){return;}
void jsr(){return;}
void ret(){return;}
void tableswitch(){return;}
void lookupswitch(){return;}
void ireturn(){return;}
void lreturn(){return;}
void freturn(){return;}
void dreturn(){return;}
void areturn(){return;}
void return_(){return;}

//REFERÊNCIAS
void getstatic(){return;}
void putstatic(){return;}
void getfield(){return;}
void putfield(){return;}
void invokevirtual(){return;}
void invokespecial(){return;}
void invokestatic(){return;}
void invokeinterface(){return;}
// void invokedynamic(){return;}
void new(){return;}
void newarray(){return;}
void anewarray(){return;}
void arraylength(){return;}
// void athrow(){return;}
// void checkcast(){return;}
// void instanceof(){return;}
// void monitorenter(){return;}
// void monitorexit(){return;}

//EXTENDIDO
void wide(){return;}
void multianewarray(){return;}
void ifnull(){return;}
void ifnonnull(){return;}
void goto_w(){return;}
void jsr_w(){return;}

// /*encontrar e carregar na array de classes object.class, classe presente no 
// ** pacote java.lang. Todas as classes em java diretamenten ou indiretamente
// ** deriva de class object, portanto é necessário carregá-la no array de classes
// ** antes de carregar o .class passado pela linha de comando.
// ** class object implementa metodos que provê algumas funcionalidades
// ** nas outras classes java.*/	

#include "../headers/carregador.h"
#include "../headers/leitor.h"
bool loaded = false;

int32_t java_lang_object(char * ObjectClass){
	
	int aux;

	if(!loaded){
		loaded = true;
		methodArea.count_class = 0;
	}

	printf("ObjectClass = %s\n", ObjectClass);
	for(int32_t i = 0; i < methodArea.count_class; i++){
		if(strcmp(ObjectClass, retorneNomeClass(methodArea.tabela_classe[i])) == 0){
			return i;
		}
	}

	printf("methodArea.count_class = %d\n", methodArea.count_class);
	methodArea.count_class++;
	aux = methodArea.count_class;

	cFile * arrayClassTemp = NULL;

	arrayClassTemp = (cFile *)realloc(methodArea.tabela_classe, (sizeof(cFile *) * aux));
	// printf("Ponteiro temporario: %d\n", *arrayClassTemp);

	methodArea.tabela_classe = (cFile *)calloc(1, sizeof(cFile*));
	methodArea.tabela_classe = arrayClassTemp;

	char *destino = malloc(strlen(ObjectClass) + 10);
	if(strstr(ObjectClass, ".class") != NULL){
		sprintf(destino, "%s", ObjectClass);
	}else{
		sprintf(destino, "%s.class", ObjectClass);
	}

	printf("DESTINO: %s\n", destino);

	// methodArea.tabela_classe[methodArea.count_class] = init_leitor(destino);
	printf("DESTINO = %s\n", destino);
	return 0;
}

char * retorneNomeClass(cFile class){
	uint16_t thisClass = class.this_class;
	uint16_t nameIndex = (class.constant_pool[thisClass]).info[0].u2;

	char * retorno = (char *) malloc((class.constant_pool[nameIndex]).info[0].u2);
	uint16_t index = class.constant_pool[nameIndex].info[0].u2; 

	printf("CHAMADO retorneNomeClass\n");

	for(int i = 0; i < index; i++){
		// retorno[i] = (char )(class.constant_pool[nameIndex]).info[1].array;
	}

	printf("retorno = %s\n", retorno);
	return retorno;
}
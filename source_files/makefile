all: build clean

build: leitor.o exibidor.o carregador.o interface.o instructions.o frame.o main.o
	@echo "Criando executavel...Pronto!"
	@gcc leitor.o exibidor.o interface.o carregador.o main.o instructions.o frame.o -ansi -std=c99  -o jvm -Wall -g -lm

main.o: main.c
	@echo "Compilando..."
	@gcc -c -ansi -Wall -std=c99 main.c -g

carregador.o: carregador.c
	@gcc -c -ansi -Wall -std=c99 carregador.c -g

instructions.o: instructions.c
	@gcc -c -ansi -Wall -std=c99 instructions.c -g

leitor.o: leitor.c
	@gcc -c -ansi -Wall -std=c99 leitor.c  -g

exibidor.o: exibidor.c
	@gcc -c -ansi -Wall -std=c99 exibidor.c  -g

interface.o: interface.c
	@gcc -c -ansi -Wall -std=c99 interface.c  -g

frame.o: frame.c
	@gcc -c -ansi -Wall -std=c99 frame.c -g
	
clean:
	@rm *.o
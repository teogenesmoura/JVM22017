all: build clean

build: leitor.o exibidor.o interface.o main.o
	@echo "Criando executavel...Pronto!"
	@gcc leitor.o exibidor.o interface.o main.o -ansi -std=c99 -o jvm -Wall -g -lm

main.o: main.c
	@echo "Compilando..."
	@gcc -c main.c -g

leitor.o: leitor.c
	@gcc -c leitor.c -g

exibidor.o: exibidor.c
	@gcc -c exibidor.c -g

interface.o: interface.c
	@gcc -c interface.c -g

clean:
	@rm *.o

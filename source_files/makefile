all: build clean

build: leitor.o exibidor.o interface.o decoder.o instructions.o frame.o main.o
	@echo "Criando executavel...Pronto!"
	@gcc leitor.o exibidor.o interface.o main.o instructions.o frame.o -ansi -std=c99  -o jvm -Wall -g -lm

main.o: main.c
	@echo "Compilando..."
	@gcc -c -ansi -Wall -std=c99 main.c  -g

instructions.o: instructions.c
	@gcc -c -ansi -Wall -std=c99 instructions.c -g

decoder.o: decoder.c
	@gcc -c -ansi -Wall -std=c99 decoder.c  -g

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
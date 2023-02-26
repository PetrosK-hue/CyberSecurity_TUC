demoprogram: simple_crypto.c simple_crypto.o demoprogram.c demoprogram.o simple_crypto.o
	gcc -g simple_crypto.c -c
	gcc demoprogram.c -c
	gcc simple_crypto.o demoprogram.o -o demoprogram

clean:
	rm -f simple_crypto.o demoprogram.o ./demoprogram de
all: bch

objects = main.o test_bch.o ecc.o bch.o rand.o rng.o makeRandomInput.o
cflags = -O3 -std=c99 -Wall -DNDEBUG

OBJS_BCH = test_bch.o ecc.o bch.o rand.o rng.o makeRandomInput.o

bch : $(objects)
	gcc -o bch $(objects)  -lcrypto   

main.o: main.c test_bch.h lac_param.h
	gcc -c main.c $(cflags)

ecc.o: ecc.c bch.h ecc.h lac_param.h 
	gcc -c ecc.c $(cflags)

bch.o: bch.c bch.h test_bch.h ecc.h
	gcc -c bch.c $(cflags)

rand.o: rand.c lac_param.h rand.h
	gcc -c rand.c $(cflags) 

rng.o: rng.c rng.h
	gcc -c rng.c $(cflags) 

makeRandomInput.o: makeRandomInput.c makeRandomInput.h
	gcc -c makeRandomInput.c $(cflags)

clean:
	rm -f bch bch.exemak $(objects)


          

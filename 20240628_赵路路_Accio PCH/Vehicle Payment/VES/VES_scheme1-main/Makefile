CFLAGS=-O3 -march=native -mtune=native -ggdb
RELIC_ROOT = ../..

all: 
	gcc ${CFLAGS} src/*.c target-gmp/lib/librelic_s.a -o main -lgmp -I ${RELIC_ROOT}/include -I target-gmp/include -I inc

lib:
	mkdir -p target-gmp
	cd target-gmp; ../scheme1.sh ${RELIC_ROOT}/../; make

clean:
	rm -rf target-gmp *.o main




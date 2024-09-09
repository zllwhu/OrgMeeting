#!/bin/sh
cmake -DCHECK=off -DARITH=gmp -DFP_PRIME=256 -DEP_PRECO=on -DEP_PLAIN=on -DEC_ENDOM=on -DFP_METHD="INTEG;COMBA;COMBA;MONTY;MONTY;LOWER;SLIDE" -DBN_PRECI=6144 -DALLOC=DYNAMIC -DCFLAGS="-O3 -funroll-loops -fomit-frame-pointer -march=native -mtune=native"  $1

OUTDIR=./bin
GCC_FLAGS=-Wall
LINK_FLAGS=-luring

default: part1 part2 part3 part4

part1:
	gcc $(GCC_FLAGS) -o $(OUTDIR)/part1 part1.c $(LINK_FLAGS)

part2:
	gcc $(GCC_FLAGS) -o $(OUTDIR)/part2 part2.c $(LINK_FLAGS)

part3:
	gcc $(GCC_FLAGS) -o $(OUTDIR)/part3 part3.c $(LINK_FLAGS)

part4:
	gcc $(GCC_FLAGS) -o $(OUTDIR)/part4 part4.c $(LINK_FLAGS)

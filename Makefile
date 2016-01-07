
all: a.out

a.out: readelf_notes.c
	gcc readelf_notes.c -g -O0


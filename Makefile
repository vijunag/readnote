
all: a.out

a.out: readelf_notes.c
	gcc readelf_notes.c -g -O0

main: test/main.c
	gcc $^ -g -O0 -o $@

clean: main
	rm -rf $^


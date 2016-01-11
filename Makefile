
all: readelf

readelf: readelf_notes.c
	gcc $^ -g -O0 -o $@

test/main: test/main.c
	gcc $^ -g -O0 -o $@

clean: test/main readelf
	rm -rf $^


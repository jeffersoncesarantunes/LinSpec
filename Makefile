CC=gcc
CFLAGS=-Isrc -Wall

linspec: src/main.c src/memory_audit.c src/system_audit.c
	$(CC) $(CFLAGS) -o linspec src/main.c src/memory_audit.c src/system_audit.c

clean:
	rm -f linspec

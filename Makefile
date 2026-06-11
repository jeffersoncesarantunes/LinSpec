CC=gcc
CFLAGS=-Isrc -Wall -Wextra -Wpedantic -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE
LDFLAGS=-pie -Wl,-z,relro,-z,now
TARGET=linspec
SRC=src/main.c src/memory_audit.c src/system_audit.c

$(TARGET): $(SRC)
	@$(CC) $(CFLAGS) $(LDFLAGS) -o $(TARGET) $(SRC)
	@echo "OK Build successful."

clean:
	@echo "Clean."
	@rm -f $(TARGET)

.PHONY: clean

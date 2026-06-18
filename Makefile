CC=gcc
CFLAGS=-Isrc -Wall -Wextra -Wpedantic -O2 -std=c99 -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE
LDFLAGS=-pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack
TARGET=linspec
SRC=src/main.c src/memory_audit.c src/system_audit.c

$(TARGET): $(SRC)
	@$(CC) $(CFLAGS) $(LDFLAGS) -o $(TARGET) $(SRC)
	@strip $(TARGET)
	@echo "OK Build successful."

clean:
	@echo "Clean."
	@rm -f $(TARGET)

.PHONY: clean

CC=gcc
CFLAGS=-Isrc -Wall -Wextra -Wpedantic -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong
TARGET=linspec
SRC=src/main.c src/memory_audit.c src/system_audit.c

$(TARGET): $(SRC)
	@$(CC) $(CFLAGS) -o $(TARGET) $(SRC)
	@echo "🟢 Build successful."

clean:
	@echo "🧹 Clean."
	@rm -f $(TARGET)

.PHONY: clean

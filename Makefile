CC=gcc
CFLAGS=-Isrc -Wall -Wextra
TARGET=linspec
SRC=src/main.c src/memory_audit.c src/system_audit.c

$(TARGET): $(SRC)
	@$(CC) $(CFLAGS) -o $(TARGET) $(SRC)
	@echo "✔ Build successful! 🟢"

clean:
	@echo "🧹 Cleaning project artifacts..."
	@rm -f $(TARGET)
	@echo "✔ Clean complete. 🟢"

.PHONY: clean

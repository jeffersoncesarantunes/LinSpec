CC=gcc
CFLAGS=-Isrc -Wall -Wextra -Wpedantic -O2 -std=c99 -D_FORTIFY_SOURCE=2 \
       -fstack-protector-strong -fPIE -Wformat -Wformat-security \
       -Wconversion -Wsign-conversion -Wshadow -Wstrict-overflow=4
LDFLAGS=-pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack -Wl,-z,separate-code
TARGET=linspec
SRC=src/main.c src/system_audit.c

.PHONY: all clean test install uninstall lint docker

all: $(TARGET)

$(TARGET): $(SRC) src/checks.h
	@$(CC) $(CFLAGS) $(LDFLAGS) -o $(TARGET) $(SRC)
	@strip $(TARGET)
	@echo "OK Build successful."
	@mkdir -p profiles reports

debug: CFLAGS += -g -O0 -DDEBUG
debug: LDFLAGS += -g
debug: $(TARGET)
	@echo "OK Debug build."

profiles:
	@mkdir -p profiles

reports:
	@mkdir -p reports

test: $(TARGET) test_runner
	@echo "Running tests..."
	@bash tests/run_tests.sh

test_runner:
	@mkdir -p profiles reports

install: $(TARGET)
	@install -m 0755 -d $(DESTDIR)/usr/local/bin
	@install -m 0755 $(TARGET) $(DESTDIR)/usr/local/bin/$(TARGET)
	@install -m 0755 -d $(DESTDIR)/usr/local/share/linspec/profiles
	@cp -r profiles/* $(DESTDIR)/usr/local/share/linspec/profiles/ 2>/dev/null || true
	@echo "OK Installed to $(DESTDIR)/usr/local/bin/$(TARGET)"

uninstall:
	@rm -f $(DESTDIR)/usr/local/bin/$(TARGET)
	@rm -rf $(DESTDIR)/usr/local/share/linspec
	@echo "OK Uninstalled."

lint:
	@which cppcheck >/dev/null 2>&1 && \
		cppcheck --enable=all --std=c99 --suppress=missingIncludeSystem \
		--error-exitcode=1 -Isrc $(SRC) || \
		echo "Warning: cppcheck not installed, skipping."
	@which scan-build >/dev/null 2>&1 && \
		scan-build --status-bugs make clean all 2>/dev/null || \
		echo "Warning: clang scan-build not installed, skipping."

docker:
	@docker build -t linspec:latest .
	@echo "OK Docker image built: linspec:latest"

clean:
	@rm -f $(TARGET)
	@rm -rf build/
	@echo "Clean."

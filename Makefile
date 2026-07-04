CC=gcc
CFLAGS=-Isrc -Iinclude -Wall -Wextra -Wpedantic -O2 -std=c99 -D_FORTIFY_SOURCE=2 \
       -fstack-protector-strong -fPIE -Wformat -Wformat-security \
       -Wconversion -Wsign-conversion -Wshadow -Wstrict-overflow=4
LDFLAGS=-pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack -Wl,-z,separate-code
TARGET=linspec
REMEDIATOR=remediator
SRC=src/main.c src/system_audit.c
REMEDIATOR_SRC=src/remediator.c

ifdef STATIC
CFLAGS += -static
endif

.PHONY: all clean test install uninstall lint docker remediator

all: $(TARGET) $(REMEDIATOR)

$(TARGET): $(SRC) src/checks.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(TARGET) $(SRC)
	strip $(TARGET)
	echo "✅ Build successful."
	mkdir -p profiles reports

$(REMEDIATOR): $(REMEDIATOR_SRC) include/remediator.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(REMEDIATOR) $(REMEDIATOR_SRC)
	strip $(REMEDIATOR)
	echo "✅ Remediation module built."

debug: CFLAGS += -g -O0 -DDEBUG
debug: LDFLAGS += -g
debug: $(TARGET)
	echo "🔧 Debug build."

profiles:
	mkdir -p profiles

reports:
	mkdir -p reports

test: $(TARGET) test_runner
	echo "🧪 Running tests..."
	bash tests/run_tests.sh

test_runner:
	mkdir -p profiles reports

MANDIR ?= $(DESTDIR)/usr/local/share/man/man1

install: $(TARGET) $(REMEDIATOR) install-man
	install -m 0755 -d $(DESTDIR)/usr/local/bin
	install -m 0755 $(TARGET) $(DESTDIR)/usr/local/bin/$(TARGET)
	install -m 0755 $(REMEDIATOR) $(DESTDIR)/usr/local/bin/$(REMEDIATOR)
	install -m 0755 -d $(DESTDIR)/usr/local/share/linspec/profiles
	cp -r profiles/* $(DESTDIR)/usr/local/share/linspec/profiles/ 2>/dev/null || true
	echo "✅ Installed to $(DESTDIR)/usr/local/bin/$(TARGET), $(REMEDIATOR)"

install-man:
	install -m 0755 -d $(MANDIR)
	install -m 644 man/linspec.1 $(MANDIR)/linspec.1
	echo "  📄 Installed man page to $(MANDIR)"

uninstall:
	rm -f $(DESTDIR)/usr/local/bin/$(TARGET)
	rm -f $(DESTDIR)/usr/local/bin/$(REMEDIATOR)
	rm -rf $(DESTDIR)/usr/local/share/linspec
	rm -f $(MANDIR)/linspec.1
	-rmdir $(MANDIR) 2>/dev/null; true
	echo "🗑 Uninstalled."
	rm -f $(MANDIR)/linspec.1
	-rmdir $(MANDIR) 2>/dev/null; true
	echo "🗑 Uninstalled."

lint:
	which cppcheck >/dev/null 2>&1 && \
		cppcheck --enable=all --std=c99 --suppress=missingIncludeSystem \
		--error-exitcode=1 -Isrc $(SRC) || \
		echo "Warning: cppcheck not installed, skipping."
	which scan-build >/dev/null 2>&1 && \
		scan-build --status-bugs make clean all 2>/dev/null || \
		echo "Warning: clang scan-build not installed, skipping."

docker:
	docker build -t linspec:latest .
	echo "🐳 Docker image built: linspec:latest"

clean:
	rm -f $(TARGET) $(REMEDIATOR)
	rm -rf build/
	echo "🧹 Clean."

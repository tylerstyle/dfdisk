PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
DOCDIR ?= $(PREFIX)/share/doc/dfdisk

.PHONY: all build release test clean install uninstall nix-build flake-build deb

all: build

build:
	cargo build

release:
	cargo build --release

test:
	cargo test

clean:
	cargo clean

nix-build:
	nix-build default.nix

flake-build:
	nix build

deb:
	cargo deb

install: release
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 target/release/dfdisk $(DESTDIR)$(BINDIR)/dfdisk
	install -d $(DESTDIR)$(DOCDIR)
	install -m 644 README.md $(DESTDIR)$(DOCDIR)/README.md
	install -m 644 LICENSE $(DESTDIR)$(DOCDIR)/LICENSE

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/dfdisk
	rm -rf $(DESTDIR)$(DOCDIR)

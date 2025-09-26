.PHONY: build test check fmt clippy clean install

build:
	cargo build --release

test:
	cargo test

check:
	cargo check

fmt:
	cargo fmt --all

clippy:
	cargo clippy --all-targets --all-features -- -D warnings

clean:
	cargo clean

install: build
	sudo cp target/release/libvmod_cel.so /usr/lib/varnish-plus/vmods/
	sudo ldconfig

# Install with versioned filename
install-versioned: build
	$(eval VERSION := $(shell cargo metadata --format-version=1 | jq -r '.packages[] | select(.name=="vmod_cel") | .version'))
	$(eval MAJOR := $(shell echo $(VERSION) | cut -d. -f1))
	sudo cp target/release/libvmod_cel.so /usr/lib/varnish/vmods/libvmod_cel.so.$(VERSION)
	sudo ln -sf libvmod_cel.so.$(VERSION) /usr/lib/varnish/vmods/libvmod_cel.so.$(MAJOR)
	sudo ln -sf libvmod_cel.so.$(VERSION) /usr/lib/varnish/vmods/libvmod_cel.so
	sudo ldconfig

varnishtest: build
	varnishtest -D vmod=$(PWD)/target/release/libvmod_cel.so tests/*.vtc

all: fmt clippy test build

ci: all varnishtest
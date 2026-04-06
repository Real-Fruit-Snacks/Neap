.PHONY: build clean compressed current

current:
	@mkdir -p bin
	cargo build --release
	@cp target/release/neap bin/ 2>/dev/null || cp target/release/neap.exe bin/ 2>/dev/null || true

build: clean current
	cross build --release --target x86_64-unknown-linux-musl && cp target/x86_64-unknown-linux-musl/release/neap bin/neapx64 || true
	cross build --release --target i686-unknown-linux-musl && cp target/i686-unknown-linux-musl/release/neap bin/neapx86 || true
	cross build --release --target x86_64-pc-windows-gnu && cp target/x86_64-pc-windows-gnu/release/neap.exe bin/neapx64.exe || true
	cross build --release --target i686-pc-windows-gnu && cp target/i686-pc-windows-gnu/release/neap.exe bin/neapx86.exe || true
	cross build --release --target aarch64-unknown-linux-musl && cp target/aarch64-unknown-linux-musl/release/neap bin/neap-linux-arm64 || true
	cross build --release --target aarch64-apple-darwin && cp target/aarch64-apple-darwin/release/neap bin/neap-macos-arm64 || true
	cross build --release --target x86_64-apple-darwin && cp target/x86_64-apple-darwin/release/neap bin/neap-macos-x64 || true

clean:
	rm -f bin/neap*

compressed: build
	@for f in $$(ls bin/neap* 2>/dev/null); do upx -o "bin/upx_$$(basename $$f)" "$$f" 2>/dev/null || true; done

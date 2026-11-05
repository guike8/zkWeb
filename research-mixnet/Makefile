.PHONY: test build build-proof test-proof demo vet compare

# Keep optional Rust proof dependencies out of the ordinary Go build.
PROOF_TARGET_DIR ?= proof-verifier/target

# The upstream algorithm registry requires CGO and a C compiler, even though
# this experiment explicitly selects X25519 (no post-quantum claim).
test:
	# Fixed-epoch transport fixtures must not compete with parallel test runs.
	go test -race -count=1 -p 1 -parallel 1 ./...
vet:
	go vet ./...
build:
	go build -trimpath -o bin/zkweb ./cmd/research-mixnet
	ln -sf zkweb bin/research-mixnet
build-proof:
	RUSTC="$$(rustup which --toolchain 1.99.0 rustc)" RUSTDOC="$$(rustup which --toolchain 1.99.0 rustdoc)" CARGO_TARGET_DIR="$(abspath $(PROOF_TARGET_DIR))" rustup run 1.99.0 cargo build --locked --release --manifest-path proof-verifier/Cargo.toml
	mkdir -p bin
	cp "$(PROOF_TARGET_DIR)/release/zkweb-tlsn-verify" bin/zkweb-tlsn-verify
test-proof: build-proof
	RUSTC="$$(rustup which --toolchain 1.99.0 rustc)" RUSTDOC="$$(rustup which --toolchain 1.99.0 rustdoc)" CARGO_TARGET_DIR="$(abspath $(PROOF_TARGET_DIR))" rustup run 1.99.0 cargo test --locked --manifest-path proof-verifier/Cargo.toml
	ZKWEB_TLSN_BACKEND="$(abspath bin/zkweb-tlsn-verify)" go test -race -count=1 ./internal/proof -run TestTLSNBackendIntegration
demo:
	go run ./cmd/research-mixnet demo
compare: build
	./bin/zkweb compare --output-dir evidence/process-comparison

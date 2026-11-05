.PHONY: test build build-proof test-proof build-private test-private build-zk test-zk test-zk-live demo vet compare

# Keep optional Rust proof dependencies out of the ordinary Go build.
PROOF_TARGET_DIR ?= proof-verifier/target
PRIVATE_TARGET_DIR ?= private-request/target
ZK_TARGET_DIR ?= zk-listener/target

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
build-private:
	RUSTC="$$(rustup which --toolchain 1.99.0 rustc)" RUSTDOC="$$(rustup which --toolchain 1.99.0 rustdoc)" CARGO_TARGET_DIR="$(abspath $(PRIVATE_TARGET_DIR))" rustup run 1.99.0 cargo build --locked --release --manifest-path private-request/Cargo.toml
	mkdir -p bin
	cp "$(PRIVATE_TARGET_DIR)/release/zkweb-private" bin/zkweb-private
test-private: build build-private
	RUSTC="$$(rustup which --toolchain 1.99.0 rustc)" RUSTDOC="$$(rustup which --toolchain 1.99.0 rustdoc)" CARGO_TARGET_DIR="$(abspath $(PRIVATE_TARGET_DIR))" rustup run 1.99.0 cargo test --locked --release --manifest-path private-request/Cargo.toml -- --test-threads=1
	ZKWEB_PRIVATE_CLI="$(abspath bin/zkweb)" go test -race -count=1 ./internal/privatee2e -run TestPrivateBackendIntegration -timeout 20m
build-zk:
	RUSTC="$$(rustup which --toolchain 1.99.0 rustc)" RUSTDOC="$$(rustup which --toolchain 1.99.0 rustdoc)" CARGO_TARGET_DIR="$(abspath $(ZK_TARGET_DIR))" rustup run 1.99.0 cargo build --locked --release --manifest-path zk-listener/Cargo.toml
	mkdir -p bin
	cp "$(ZK_TARGET_DIR)/release/zkweb-zk-listener" bin/zkweb-zk-listener
test-zk: build build-zk
	RUSTC="$$(rustup which --toolchain 1.99.0 rustc)" RUSTDOC="$$(rustup which --toolchain 1.99.0 rustdoc)" CARGO_TARGET_DIR="$(abspath $(ZK_TARGET_DIR))" rustup run 1.99.0 cargo test --locked --release --manifest-path zk-listener/Cargo.toml -- --test-threads=1
	ZKWEB_ZK_CLI="$(abspath bin/zkweb)" go test -race -count=1 -p 1 ./internal/zke2e ./internal/zkapi_e2e -run 'TestZK.*Integration' -timeout 5m
# Explicit network opt-in: public GitHub reads and disposable httpbingo echoes.
# Optional ZKWEB_ZK_LIVE_REPORT / ZKWEB_ZK_LIVE_METHODS_REPORT save JSON evidence.
test-zk-live: build build-zk
	ZKWEB_ZK_LIVE=1 ZKWEB_ZK_CLI="$(abspath bin/zkweb)" go test -race -count=1 -v ./internal/zkapi_e2e -run '^TestZKAPIGatewayLive(External|Methods)$$' -timeout 5m
demo:
	go run ./cmd/research-mixnet demo
compare: build
	./bin/zkweb compare --output-dir evidence/process-comparison

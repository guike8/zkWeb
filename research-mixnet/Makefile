.PHONY: test build demo vet compare

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
demo:
	go run ./cmd/research-mixnet demo
compare: build
	./bin/zkweb compare --output-dir evidence/process-comparison

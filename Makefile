.PHONY: build test clean

build:
	go build -o sshmonkey ./cmd/sshmonkey

test:
	go test ./... -v

clean:
	rm -f sshmonkey

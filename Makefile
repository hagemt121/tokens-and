GO ?= $(shell command -v go)

all: demo
.PHONY: all

clean:
	@git clean -dix
.PHONY: clean

demo:
	@env "$(GO)" run ./demo
.PHONY: demo

test:
	@env "$(GO)" test -v ./...
.PHONY: test

tidy:
	@env "$(GO)" mod tidy
.PHONY: test

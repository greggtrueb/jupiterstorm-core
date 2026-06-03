.PHONY: build vet test pre-push install-hooks

build:
	go build ./...

vet:
	go vet ./...

test:
	go test -race ./...

pre-push: vet build test

install-hooks:
	@mkdir -p .git/hooks
	@printf '#!/bin/sh\nmake pre-push\n' > .git/hooks/pre-push
	@chmod +x .git/hooks/pre-push
	@echo "pre-push hook installed"

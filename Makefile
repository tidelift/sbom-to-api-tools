CMDS = $(shell find cmd/  -mindepth 1  -maxdepth 1 -type d)
SRC = $(shell find . -type f -name '*.go')

GOLANGCI_LINT:=$(shell command -v golangci-lint 2> /dev/null)

all: build

all-cross: build-windows build-linux-x86 build-linux-arm build-mac-arm

build: $(SRC)
	for d in $(CMDS) ; do pushd $$d > /dev/null ; CGO_ENABLED=0 go build -o ../../bin/ ; popd > /dev/null ; done

build-windows: $(SRC)
	mkdir -p bin/windows || /bin/true
	for d in $(CMDS) ; do pushd $$d > /dev/null ; GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o ../../bin/windows ; popd > /dev/null ; done

build-linux-x86: $(SRC)
	mkdir -p bin/linux-x86 || /bin/true
	for d in $(CMDS) ; do pushd $$d > /dev/null ; GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o ../../bin/linux-x86 ; popd > /dev/null ; done

build-linux-arm: $(SRC)
	mkdir -p bin/linux-arm || /bin/true
	for d in $(CMDS) ; do pushd $$d > /dev/null ; GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o ../../bin/linux-arm ; popd > /dev/null ; done

build-mac-arm: $(SRC)
	mkdir -p bin/mac-arm || /bin/true
	for d in $(CMDS) ; do pushd $$d > /dev/null ; GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -o ../../bin/mac-arm ; popd > /dev/null ; done

clean:
	go clean
	rm -f bin/*

linter_installed:
ifndef GOLANGCI_LINT
	$(error "golangci-lint is not available, please install https://github.com/golangci/golangci-lint")
endif

lint: linter_installed
	# https://github.com/golangci/golangci-lint#disabled-by-default-linters--e--enable
	golangci-lint run

fix: linter_installed
	golangci-lint run --fix
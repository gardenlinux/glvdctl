APP_NAME := glvdctl
GO_FILES := $(shell find . -type f -name '*.go')
BUILD_DIR := bin

.PHONY: all build clean test fmt

all: build

build: $(GO_FILES)
	mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(APP_NAME) .

clean:
	rm -rf $(BUILD_DIR)

test:
	go test ./...

fmt:
	go fmt ./...

.PHONY: install
install:
	go install .

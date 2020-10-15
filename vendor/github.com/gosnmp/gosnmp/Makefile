.PHONY: test lint lint-all lint-examples tools

test:
	go test *.go

lint:
	golangci-lint run ./...

tools:
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(GOPATH)/bin v1.26.0

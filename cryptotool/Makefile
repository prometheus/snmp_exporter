.DEFAULT_GOAL := build

.PHONY: test
test: build ## Run tests in atomic mode
	echo 'mode: atomic' > coverage.out && go test -covermode=atomic -coverprofile=coverage.out -v -race -timeout=30s ./...

.PHONY: cover
cover: test ## Run test and then give text coverage report
	go tool cover -func=coverage.out

.PHONY: coverhtml
coverhtml: test ## Run test and then give html coverage report
	go tool cover -html=coverage.out

.PHONY: build
build: ## Build binary
	go build -v ./...

.PHONY: clean
clean: ## Remove tem files
	go clean

.PHONY: help
help:   # From http://marmelab.com/blog/2016/02/29/auto-documented-makefile.html
	@echo
	@echo "  make commands available in cryptotool:"
	@echo
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
	@echo


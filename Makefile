DOCKER_IMAGE_NAME ?= snmp_exporter
DOCKER_REPO_NAME := gcr.io/npav-172917/
DOCKER_VER := $(if $(DOCKER_VER),$(DOCKER_VER),$(shell whoami)-dev)
BIN_NAME := bin/alpine-$(DOCKER_IMAGE_NAME)

GO_REPOSITORY_PATH := github.com/accedian-tt/$(DOCKER_IMAGE_NAME)
GO_SDK_IMAGE := gcr.io/npav-172917/docker-go-sdk
GO_SDK_VERSION := 0.36.0-alpine
GOPATH := $(GOPATH)

PROJECT_BASE_PATH := $(PWD)
DATE_TAG := $(shell date -u +"%Y%m%dT%H%M%SZ")

all: test docker

docker: dockerbin
	docker build -t $(DOCKER_REPO_NAME)$(DOCKER_IMAGE_NAME):$(DOCKER_VER) .
push: docker
	docker push $(DOCKER_REPO_NAME)$(DOCKER_IMAGE_NAME):$(DOCKER_VER)
build-test: docker
	docker tag $(DOCKER_REPO_NAME)$(DOCKER_IMAGE_NAME):$(DOCKER_VER) $(DOCKER_REPO_NAME)$(DOCKER_IMAGE_NAME):test

test:
	docker run -it --rm \
		-e GOPATH=/root/go \
		-v "$(GOPATH):/root/go" \
		-v "$(PROJECT_BASE_PATH):/root/workingdir" \
		-w "/root/workingdir" \
		$(GO_SDK_IMAGE):$(GO_SDK_VERSION) go test -p 1 ./...

dockerbin: .FORCE
	echo "PATH is $(GOPATH)"
	docker run -it --rm \
		-e GOPATH=/root/go \
		-v "$(GOPATH):/root/go" \
		-v "$(PROJECT_BASE_PATH):/root/workingdir" \
		-w "/root/workingdir" \
		$(GO_SDK_IMAGE):$(GO_SDK_VERSION) go build -o $(BIN_NAME)

#licenseinventory:
#	docker run -it --rm \
#		-e GOPATH=/root/go \
#		-v "$(GOPATH):/root/go" \
#		-w "/root/go/src/$(GO_REPOSITORY_PATH)" \
#		$(GO_SDK_IMAGE):$(GO_SDK_VERSION) printLicenses.sh

.FORCE:
clean:
	rm -rf bin
	rm -f licenses.csv licenses.md licences_groups.md licenses_groups.csv

debugfile:
	docker build . -t gcr.io/npav-172917/snmp-exporter:debug-$(DATE_TAG)
	docker save gcr.io/npav-172917/snmp-exporter:debug-$(DATE_TAG) --output  snmp-exporter:debug-$(DATE_TAG).tar

accpush:
	docker build . -t gcr.io/npav-172917/snmp-exporter:$(DATE_TAG)
	docker push gcr.io/npav-172917/snmp-exporter:$(DATE_TAG)
	docker save gcr.io/npav-172917/snmp-exporter:$(DATE_TAG) --output  snmp-exporter:$(DATE_TAG).tar

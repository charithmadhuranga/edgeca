GO111MODULE=on # Enable module mode
GIT_VERSION=$(shell git describe --tags --abbrev=0 | sed 's/v//')
GOFLAGS=-ldflags "-X github.com/edgesec-org/edgeca.Version=$(GIT_VERSION)"

all: 
	echo $(GOFLAGS)
	go mod tidy
	go get ./...
	go build $(GOFLAGS) -o bin/edgeca ./cmd/edgeca 

docker:
	docker build --build-arg version="$(GIT_VERSION)" -t edgesec/edgeca .
	docker push edgesec/edgeca

snapcraft:
	snapcraft --use-lxd

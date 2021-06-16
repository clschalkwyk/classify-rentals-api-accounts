.PHONY: build clean deploy

build:
	dep ensure -v
	env GOOS=linux go build -ldflags="-s -w" -o bin/account-login account/login/main.go
	env GOOS=linux go build -ldflags="-s -w" -o bin/account-signup account/signup/main.go

clean:
	rm -rf ./bin ./vendor Gopkg.lock

deploy: clean build
	sls deploy --verbose

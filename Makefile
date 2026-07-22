test:
	cd api && ENV_FILE=.env.test go test ./...

build-api:
	cd api && CGO_ENABLED=0 GOOS=linux go build -o vpn-api ./cmd/api
	cd api && CGO_ENABLED=0 GOOS=linux go build -o vpn-createadmin ./cmd/createadmin

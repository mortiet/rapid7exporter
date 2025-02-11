CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags "-s -w" -a -installsuffix cgo .

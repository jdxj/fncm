file := fncm.out

.PHONY: build
build:
	go build -ldflags '-s -w' -o $(file) ./*.go
	upx --best $(file)

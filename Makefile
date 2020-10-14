.PHONY: build


generate:
	@echo "[*] Minifying css and js"
	@find static/ -type f -name "*.js" ! -name "*.min.*" -exec echo {} \; -exec uglifyjs -o {}.min.js {} \;
	@find static/ -type f -name "*.css" ! -name "*.min.*" -exec echo {} \; -exec uglifycss --output {}.min.css {} \;
	@echo "[OK] Done minifying things"
	@echo "[*] Embedding via parcello"
	@PARCELLO_RESOURCE_DIR=./static go generate ./...
	@echo "[OK] Done bundeling things"

build: clean generate
	@echo "[*] go mod dowload"
	@go mod download
	@echo "[*] Building for linux"
	@GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o dist/linux_amd64/goshs
	@GOOS=linux GOARCH=386 go build -ldflags="-s -w" -o dist/linux_386/goshs
	@echo "[*] Building for windows"
	@GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o dist/windows_amd64/goshs.exe
	@GOOS=windows GOARCH=386 go build -ldflags="-s -w" -o dist/windows_386/goshs.exe
	@echo "[*] Building for mac"
	@GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o dist/darwin_amd64/goshs
	@echo "[OK] App binary was created!"

run:
	@go run main.go

install:
	@go install ./...
	@echo "[OK] Application was installed to go binary directory!"

clean:
	@rm -rf ./dist
	@echo "[OK] Cleaned up!"

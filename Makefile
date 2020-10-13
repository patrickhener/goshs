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
	@echo "[*] Building for linux"
	@GOOS=linux go build -ldflags="-s -w" -o build/goshs
	@echo "[*] Building for windows"
	@GOOS=windows go build -ldflags="-s -w" -o build/goshs.exe
	@echo "[OK] App binary was created!"

run:
	@./build/goshs

install:
	@go install ./...
	@echo "[OK] Application was installed to go binary directory!"

clean:
	@rm -rf ./build
	@echo "[OK] Cleaned up!"

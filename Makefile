.PHONY: build

build: clean
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

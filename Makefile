.PHONY: build

build:
	@go build -o build
	@echo "[OK] App binary was created!"

run:
	@./build/goshs

.PHONY: build

build: clean
	@go build -o build/goshs
	@echo "[OK] App binary was created!"

run:
	@./build/goshs

install:
	@go install ./...
	@echo "[OK] Application was installed to go binary directory!"

clean:
	@rm -rf ./build
	@echo "[OK] Cleaned up!"

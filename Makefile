.PHONY: build

# uglify-js and sass needed
generate:
	@echo "[*] Minifying js and compiling scss"
	@uglifyjs -o httpserver/static/js/main.min.js assets/js/main.js
	@uglifyjs -o httpserver/static/js/color-modes.min.js assets/js/color-modes.js
	@sass --no-source-map -s compressed assets/css/style.scss httpserver/static/css/style.css
	@echo "[OK] Done minifying and compiling things"

security:
	@echo "[*] Checking with gosec"
	@gosec ./...
	@echo "[OK] No issues detected"


build: clean generate security
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
	@echo "[*] Building for arm"
	@GOOS=linux GOARCH=arm GOARM=5 go build -ldflags="-s -w" -o dist/arm_5/goshs
	@GOOS=linux GOARCH=arm GOARM=6 go build -ldflags="-s -w" -o dist/arm_6/goshs
	@GOOS=linux GOARCH=arm GOARM=7 go build -ldflags="-s -w" -o dist/arm_7/goshs
	@GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o dist/arm64_8/goshs
	@echo "[OK] App binary was created!"

run:
	@go run main.go

install:
	@go install ./...
	@echo "[OK] Application was installed to go binary directory!"

clean:
	@rm -rf ./dist
	@echo "[OK] Cleaned up!"

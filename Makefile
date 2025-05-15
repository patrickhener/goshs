.PHONY: build-all

# uglify-js and sass needed
generate:
	@echo "[*] Minifying js and compiling scss"
	@uglifyjs -o httpserver/static/js/main.min.js assets/js/main.js
	@uglifyjs -o httpserver/static/js/color-modes.min.js assets/js/color-modes.js
	@sass --no-source-map -s compressed assets/css/style.scss httpserver/static/css/style.css
	@echo "[OK] Done minifying and compiling things"
	@echo "[*] Copying embedded files to target location"
	@rm -rf httpserver/embedded
	@cp -r embedded httpserver/

security:
	@echo "[*] Checking with gosec"
	@gosec ./...
	@echo "[OK] No issues detected"


build-all: clean generate
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

build-linux: clean generate
	@echo "[*] go mod dowload"
	@go mod download
	@echo "[*] Building for linux"
	@GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o dist/linux_amd64/goshs
	@GOOS=linux GOARCH=386 go build -ldflags="-s -w" -o dist/linux_386/goshs
	@echo "[OK] App binary was created!"

build-mac: clean generate
	@echo "[*] go mod dowload"
	@go mod download
	@echo "[*] Building for mac"
	@GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o dist/darwin_amd64/goshs
	@echo "[OK] App binary was created!"

build-windows: clean generate
	@echo "[*] go mod dowload"
	@go mod download
	@echo "[*] Building for windows"
	@GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o dist/windows_amd64/goshs.exe
	@GOOS=windows GOARCH=386 go build -ldflags="-s -w" -o dist/windows_386/goshs.exe
	@echo "[OK] App binary was created!"

build-arm: clean generate
	@echo "[*] go mod dowload"
	@go mod download
	@echo "[*] Building for arm"
	@GOOS=linux GOARCH=arm GOARM=5 go build -ldflags="-s -w" -o dist/arm_5/goshs
	@GOOS=linux GOARCH=arm GOARM=6 go build -ldflags="-s -w" -o dist/arm_6/goshs
	@GOOS=linux GOARCH=arm GOARM=7 go build -ldflags="-s -w" -o dist/arm_7/goshs
	@GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o dist/arm64_8/goshs
	@echo "[OK] App binary was created!"

run-unit:
	@go test ./ca -count=1
	@go test ./cli -count=1
	@go test ./clipboard -count=1
	@go test ./config -count=1
	@go test ./logger -count=1
	@go test ./update -count=1
	@go test ./utils -count=1
	@go test ./webhook -count=1
	@go test ./ws -count=1

run-integration: clean-integration
	@go test ./integration -count=1

clean-integration:
	@mkdir -p ./integration/files
	@rm -rf ./integration/files/*
	@cp ./integration/keepFiles/test_data.txt ./integration/files/
	@mkdir ./integration/files/ACL
	@mkdir ./integration/files/ACL/testfolder
	@mkdir ./integration/files/ACLAuth
	@mkdir ./integration/files/ACLAuth/testfolder
	@cp ./integration/keepFiles/goshsACL ./integration/files/ACL/.goshs
	@cp ./integration/keepFiles/testfile.txt ./integration/files/ACL/
	@cp ./integration/keepFiles/testfile2.txt ./integration/files/ACL/
	@cp ./integration/keepFiles/testfile2.txt ./integration/files/ACL/testfolder/
	@cp ./integration/keepFiles/goshsACLAuth ./integration/files/ACLAuth/.goshs
	@cp ./integration/keepFiles/testfile.txt ./integration/files/ACLAuth/
	@cp ./integration/keepFiles/testfile2.txt ./integration/files/ACLAuth/
	@cp ./integration/keepFiles/testfile2.txt ./integration/files/ACLAuth/testfolder/
	@echo "cleaned up, ready for next test"

run-tests: run-unit run-integration

run:
	@go run main.go

install:
	@go install ./...
	@echo "[OK] Application was installed to go binary directory!"

clean:
	@rm -rf ./dist
	@echo "[OK] Cleaned up!"


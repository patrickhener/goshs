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


build-all: clean generate build-linux build-mac build-windows build-dragonfly build-freebsd build-openbsd build-netbsd

build-linux: clean generate
	@echo "[*] go mod dowload"
	@go mod download
	@echo "[*] Building for linux"
	@GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o dist/linux_amd64/goshs
	@GOOS=linux GOARCH=386 go build -ldflags="-s -w" -o dist/linux_386/goshs
	@GOOS=linux GOARCH=arm GOARM=5 go build -ldflags="-s -w" -o dist/linux_arm_5/goshs
	@GOOS=linux GOARCH=arm GOARM=6 go build -ldflags="-s -w" -o dist/linux_arm_6/goshs
	@GOOS=linux GOARCH=arm GOARM=7 go build -ldflags="-s -w" -o dist/linux_arm_7/goshs
	@GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o dist/linux_arm64_8/goshs
	@echo "[OK] App binary was created!"

build-mac: clean generate
	@echo "[*] go mod dowload"
	@go mod download
	@echo "[*] Building for mac"
	@GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o dist/darwin_amd64/goshs
	@GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o dist/darwin_arm64/goshs
	@echo "[OK] App binary was created!"

build-windows: clean generate
	@echo "[*] go mod dowload"
	@go mod download
	@echo "[*] Building for windows"
	@GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o dist/windows_amd64/goshs.exe
	@GOOS=windows GOARCH=386 go build -ldflags="-s -w" -o dist/windows_386/goshs.exe
	@GOOS=windows GOARCH=arm GOARM=5 go build -ldflags="-s -w" -o dist/windows_arm_5/goshs.exe
	@GOOS=windows GOARCH=arm GOARM=6 go build -ldflags="-s -w" -o dist/windows_arm_6/goshs.exe
	@GOOS=windows GOARCH=arm GOARM=7 go build -ldflags="-s -w" -o dist/windows_arm_7/goshs.exe
	@GOOS=windows GOARCH=arm64 go build -ldflags="-s -w" -o dist/windows_arm64_8/goshs.exe
	@echo "[OK] App binary was created!"

build-dragonfly: clean generate
	@echo "[*] go mod dowload"
	@go mod download
	@echo "[*] Building for dragonfly"
	@GOOS=dragonfly GOARCH=amd64 go build -ldflags="-s -w" -o dist/dragonfly_amd64/goshs
	@echo "[OK] App binary was created!"

build-freebsd: clean generate
	@echo "[*] go mod dowload"
	@go mod download
	@echo "[*] Building for freebsd"
	@GOOS=freebsd GOARCH=amd64 go build -ldflags="-s -w" -o dist/freebsd_amd64/goshs
	@GOOS=freebsd GOARCH=386 go build -ldflags="-s -w" -o dist/freebsd_386/goshs
	@GOOS=freebsd GOARCH=arm GOARM=5 go build -ldflags="-s -w" -o dist/freebsd_arm_5/goshs
	@GOOS=freebsd GOARCH=arm GOARM=6 go build -ldflags="-s -w" -o dist/freebsd_arm_6/goshs
	@GOOS=freebsd GOARCH=arm GOARM=7 go build -ldflags="-s -w" -o dist/freebsd_arm_7/goshs
	@GOOS=freebsd GOARCH=arm64 go build -ldflags="-s -w" -o dist/freebsd_arm64_8/goshs
	@echo "[OK] App binary was created!"

build-openbsd: clean generate
	@echo "[*] go mod dowload"
	@go mod download
	@echo "[*] Building for openbsd"
	@GOOS=openbsd GOARCH=amd64 go build -ldflags="-s -w" -o dist/openbsd_amd64/goshs
	@GOOS=openbsd GOARCH=386 go build -ldflags="-s -w" -o dist/openbsd_386/goshs
	@GOOS=openbsd GOARCH=arm GOARM=5 go build -ldflags="-s -w" -o dist/openbsd_arm_5/goshs
	@GOOS=openbsd GOARCH=arm GOARM=6 go build -ldflags="-s -w" -o dist/openbsd_arm_6/goshs
	@GOOS=openbsd GOARCH=arm GOARM=7 go build -ldflags="-s -w" -o dist/openbsd_arm_7/goshs
	@GOOS=openbsd GOARCH=arm64 go build -ldflags="-s -w" -o dist/openbsd_arm64_8/goshs
	@echo "[OK] App binary was created!"

build-netbsd: clean generate
	@echo "[*] go mod dowload"
	@go mod download
	@echo "[*] Building for netbsd"
	@GOOS=netbsd GOARCH=amd64 go build -ldflags="-s -w" -o dist/netbsd_amd64/goshs
	@GOOS=netbsd GOARCH=386 go build -ldflags="-s -w" -o dist/netbsd_386/goshs
	@GOOS=netbsd GOARCH=arm GOARM=5 go build -ldflags="-s -w" -o dist/netbsd_arm_5/goshs
	@GOOS=netbsd GOARCH=arm GOARM=6 go build -ldflags="-s -w" -o dist/netbsd_arm_6/goshs
	@GOOS=netbsd GOARCH=arm GOARM=7 go build -ldflags="-s -w" -o dist/netbsd_arm_7/goshs
	@GOOS=netbsd GOARCH=arm64 go build -ldflags="-s -w" -o dist/netbsd_arm64_8/goshs
	@echo "[OK] App binary was created!"

new-version:
ifndef VERSION
	$(error Usage: make new-version VERSION=vX.Y.Z)
endif
	@echo "Updating version to $(VERSION)..."
	@sed -i 's/var GoshsVersion = "v[^"]*"/var GoshsVersion = "$(VERSION)"/' goshsversion/version.go
	@sed -i 's|https://img.shields.io/badge/Version-v[^-]*-green|https://img.shields.io/badge/Version-$(VERSION)-green|' README.md
	@git add goshsversion/version.go README.md
	@git commit -m "New version $(VERSION)"
	@git push
	@git tag $(VERSION)
	@git push origin $(VERSION)
	@docker build -t patrickhener/goshs:$(VERSION) .
	@docker build -t patrickhener/goshs:latest .
	@docker push patrickhener/goshs:$(VERSION)
	@docker push patrickhener/goshs:latest

run-unit:
	@go test ./ca -count=1
	@go test ./cli -count=1
	@go test ./clipboard -count=1
	@go test ./config -count=1
	@go test ./logger -count=1
	@go test ./sftpserver -count=1
	@go test ./update -count=1
	@go test ./utils -count=1
	@go test ./webhook -count=1
	@go test ./ws -count=1

run-integration: clean-integration
	@go test -v ./integration -count=1

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


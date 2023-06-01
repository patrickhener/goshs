FROM golang:1.20-bullseye
ENV DEBIAN_FRONTEND=noninteractive
RUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash - && apt-get install -y nodejs
RUN npm install -g uglify-js && npm install -g sass
RUN curl -sfL https://raw.githubusercontent.com/securego/gosec/master/install.sh | sh -s -- -b $(go env GOPATH)/bin v2.11.0
COPY . /goshs
WORKDIR /goshs
RUN make build
EXPOSE 8080/tcp
EXPOSE 8080/udp
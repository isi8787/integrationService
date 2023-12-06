FROM golang:1.18-alpine

RUN mkdir -p /L1Integration/app/
WORKDIR /L1Integration/app
COPY . .

RUN apk add --no-cache git bash build-base

ENV GOPRIVATE=dev.azure.com
RUN git config --global url."https://pat:xqcc2w53dbyrykmddlrn6objz3zxihk2gtmyy47kom4ns7g7uzea@dev.azure.com".insteadOf "https://dev.azure.com"
# Download all the dependencies
RUN go get dev.azure.com/1662nd/cryptographymodules/_git/cryptographymodules.git/kryptology
RUN go get dev.azure.com/1662nd/cryptographymodules/_git/cryptographymodules.git/adaptor
RUN go get dev.azure.com/1662nd/cryptographymodules/_git/cryptographymodules.git/ecdsaoperations
RUN go mod tidy

RUN GOOS=linux GOARCH=amd64 go build 

# This container exposes port 8080 to the outside world
EXPOSE 8080

# Run the executable
CMD [ "./l1integration" ]

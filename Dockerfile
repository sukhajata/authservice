# Dockerfile References: https://docs.docker.com/engine/reference/builder/

FROM golang:1.15.2-buster AS builder

RUN mkdir /app

# Set the Current Working Directory inside the container
WORKDIR /app

# use go modules
ENV GO111MODULE=on

COPY go.mod .
COPY go.sum .

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download

# Copy go files
COPY . .

# Build the Go app
RUN CGO_ENABLED=0 GOOS=linux go build -o service ./cmd

#new image
FROM alpine:3.12.0  

RUN apk --no-cache add ca-certificates

WORKDIR /app/

# Copy the Pre-built binary file from the previous stage
COPY --from=builder /app/service .

#assign owner as 1000
#RUN chown -R 1000 authservice.git

#change user
#USER 1000

# Expose ports
EXPOSE 9030
EXPOSE 2000

# Command to run the executable
ENTRYPOINT ["./service"]

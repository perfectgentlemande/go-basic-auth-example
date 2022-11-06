FROM golang:1.19.0 AS builder

ADD . /app
WORKDIR /app
# GOOS/GOARCH as you build not from go alpine
RUN GOOS=linux GOARCH=amd64 go build -o go-basic-auth-app ./cmd/go-basic-auth-example

FROM alpine:3.16 AS app
WORKDIR /app
COPY --from=builder /app/go-basic-auth-app /app
COPY --from=builder /app/cmd/go-basic-auth-example/config.yaml /app
CMD ["/app/go-basic-auth-app"]
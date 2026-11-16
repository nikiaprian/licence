FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /license-server .

FROM alpine:3.22
RUN apk add --no-cache ca-certificates \
    && adduser -D -u 10001 app \
    && mkdir -p /data \
    && chown app:app /data
WORKDIR /app
COPY --from=build /license-server /app/license-server
USER app
ENV ADDR=:8080
ENV DATA_DIR=/data
EXPOSE 8080
VOLUME /data
ENTRYPOINT ["/app/license-server"]

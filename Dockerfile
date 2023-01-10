FROM golang:alpine3.17 as builder

WORKDIR /app
COPY . .
RUN go build -o sa-rbac-validator .

FROM alpine:3.17

WORKDIR /bin
COPY --from=builder /app/sa-rbac-validator .
CMD ["./sa-rbac-validator"]
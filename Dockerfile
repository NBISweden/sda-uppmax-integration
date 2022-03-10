FROM golang:alpine as builder

ENV GOPATH=$PWD
ENV CGO_ENABLED=0

COPY . .

RUN go build -o uppmax-integration
RUN echo "nobody:x:65534:65534:nobody:/:/sbin/nologin" > passwd

FROM scratch

COPY --from=builder /go/passwd /etc/passwd
COPY --from=builder /go/uppmax-integration /usr/bin/
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

EXPOSE 8080

USER 65534
ENTRYPOINT [ "/usr/bin/uppmax-integration" ]
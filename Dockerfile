FROM alpine:3.24 AS builder
RUN apk add --no-cache gcc musl-dev make
WORKDIR /src
COPY . ./
RUN make

FROM scratch
COPY --from=builder /src/linspec /linspec
COPY --from=builder /etc/ssl/certs /etc/ssl/certs
USER 65534:65534
ENTRYPOINT ["/linspec"]

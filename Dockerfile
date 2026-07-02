FROM alpine:3.24 AS builder
RUN apk add --no-cache gcc musl-dev make curl
WORKDIR /src
COPY . ./
RUN make clean all STATIC=1

FROM alpine:3.24
RUN apk add --no-cache curl ca-certificates
COPY --from=builder /src/linspec /linspec
USER 65534:65534
ENTRYPOINT ["/linspec"]

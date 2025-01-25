FROM alpine:3.21 AS certs
RUN apk --no-cache add ca-certificates

FROM scratch

# Copy CA certificates from Alpine
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy our binary
COPY zero /usr/local/bin/zero

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/zero"] 

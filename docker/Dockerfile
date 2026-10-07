FROM golang:1.22-alpine AS build
WORKDIR /src
COPY node/ ./node/
WORKDIR /src/node
RUN go build -o /aduba-node .

FROM alpine:3.20
COPY --from=build /aduba-node /usr/local/bin/aduba-node
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/aduba-node","-rpc",":8080"]

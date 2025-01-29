# Simple Account Server

Simple example for an account server that issues accounts

```bash
nats-server -c ./server.conf
go run server.go --dir .
```

```bash
nsc add operator -u http://localhost:8080/jwt/v2/operator
...
nsc add account A
...
nsc add account B
...
nsc pull -A
```
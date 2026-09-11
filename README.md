# DNS Cage

DNS Cage is a zero-dependency, loopback-only DNS policy responder. It never contacts an upstream resolver.

For every valid standard DNS question:

- a built-in provider domain receives `REFUSED` (`RCODE=5`);
- every other domain receives `NXDOMAIN` (`RCODE=3`).

Malformed packets, response packets, unsupported opcodes, multiple questions, compressed question names, non-IN classes, and queries containing additional records are rejected without a response.

## Built-in provider policy

The provider list is compiled into the binary:

- `api.anthropic.com`
- `claude.ai`
- `api.openai.com`
- `chatgpt.com`
- `generativelanguage.googleapis.com`
- `gemini.google.com`
- `api.mistral.ai`
- `dashscope.aliyuncs.com`
- `openrouter.ai`

DNS Cage deliberately refuses these names rather than resolving them. A caller must use its separately governed egress path instead of obtaining provider addresses directly through DNS Cage.

## Build and test

DNS Cage requires Go 1.24 or newer.

```sh
go test -race ./...
go vet ./...
go build -o dns-cage .
```

The test suite covers policy decisions, response-header semantics, malformed DNS messages, maximum-length names, concurrent UDP clients, repeated DNS-over-TCP frames, short writes, and bind-address validation.

## Run

The default address is `127.0.0.1:53` for both UDP and TCP:

```sh
go run .
```

Binding port 53 normally requires an appropriate local capability or elevated bind permission. For an unprivileged loopback port:

```sh
DNS_CAGE_BIND_ADDR=127.0.0.1:15353 go run .
```

`DNS_CAGE_BIND_ADDR` must contain a literal loopback IP address and a non-zero port. Hostnames, wildcard addresses, and non-loopback addresses are rejected. IPv6 loopback is supported with bracket notation, for example `[::1]:15353`.

## Operational boundary

DNS Cage supplies a deterministic local DNS response policy. It does not itself configure the host resolver, firewall, network namespace, or application egress path. Deployments remain responsible for directing the intended workload to DNS Cage and preventing access to other resolvers.

Queries are logged with quoted domain names. DNS Cage stores no query database, cache, credentials, or runtime state.

## License

Copyright (c) 2026 northsea-sec. All rights reserved.

No license is granted to use, copy, modify, or distribute this software unless the copyright holder provides one separately.

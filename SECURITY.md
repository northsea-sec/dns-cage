# Security Policy

## Supported version

Security fixes apply to the current default branch.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting for this repository when available. Include the affected version, reproduction conditions, expected security impact, and enough packet-level detail to reproduce the issue.

Do not include credentials, private infrastructure addresses, production packet captures, or other sensitive deployment material. If private vulnerability reporting is unavailable, open a non-sensitive issue requesting a private reporting channel; do not disclose exploit details in the issue.

## Security boundary

DNS Cage:

- binds only to a literal loopback address;
- returns deterministic DNS errors and performs no upstream resolution;
- accepts one uncompressed IN-class question per message;
- stores no DNS cache, credentials, or query database.

DNS Cage does not configure resolver settings, firewall rules, namespaces, or the separate governed egress path. A deployment must enforce those controls independently. Exposure of the listener beyond loopback, or continued access to another resolver, is outside the protection supplied by DNS Cage.

# Security

basicstation-gate decides which gateways reach your LNS and signs what they
run, so a vulnerability here can matter a lot. Please report one privately.

## Reporting

Use GitHub's private vulnerability reporting: **Security**, then **Report a
vulnerability**, on this repository. Or email joseph@pulzr.net.

Include what you found, how to reproduce it, and which version or commit.
You will get an answer within a week. Please give us a reasonable time to
fix it before you publish.

## Supported versions

The latest release, and `main`.

## In scope

- A gateway, or anyone on the network, getting in without an accepted
  credential, or with another gateway's.
- A revoked credential that keeps working past the next recheck.
- The public process reaching the signer's keys, or getting bytes signed
  that the backend did not plan.
- CUPS sending a gateway to a host that is not allowed.
- Secrets (tokens, keys) written to logs, the backend, or disk on the public
  side.
- Crashes or unbounded memory from what a gateway sends.

## Out of scope

- Rate limiting and connection floods: put a proxy or load balancer in front.
- `DEV_STATE_DIR`, which is for trying it out and is not meant to be secure.
- `TRUST_FORWARDED_CERT=true` behind a proxy that does not clear the header.
- Your backend's own decisions.

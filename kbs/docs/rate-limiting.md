# Rate Limiting

`POST /kbs/v0/auth` is unauthenticated by design and every call allocates a
session record, so an abusive client can fill the session store. KBS does not
rate-limit requests itself.

A per-client limit belongs on the reverse proxy, Ingress controller, or load
balancer in front of KBS:

- Behind a proxy, KBS only sees the proxy's address and cannot tell clients
  apart.
- The proxy sees the real client address, and its counters do not depend on
  which KBS replica serves a request.

This applies to every deployment model, whether KBS runs from the Helm chart,
the trustee-operator, or directly. Configure the limit the way the chosen proxy
documents it. For the Helm chart, see
[Per-client rate limiting](../../deployment/helm-chart/README.md#per-client-rate-limiting).

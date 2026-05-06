# Edge & Gateway AuthZ

**North-south enforcement · API gateways · identity-aware proxies**

*Where authorisation happens before the request reaches your service code — token validation, downscoping, rate-limit-as-policy, identity propagation. The complement to* Workload Identity & Service-Mesh AuthZ *for north-south traffic.*

```
terminate TLS -> validate token -> enforce policy -> propagate identity
```

Validate · Enforce · Propagate · Observe

---

## Table of Contents

1. [Topics](#slide-01--topics)
2. [Where the Edge Sits — vs In-App AuthZ](#slide-02--where-the-edge-sits--vs-in-app-authz)
3. [Token Validation at the Edge — JWT vs Introspection](#slide-03--token-validation-at-the-edge--jwt-vs-introspection)
4. [The Envoy `ext_authz` Pattern](#slide-04--the-envoy-ext_authz-pattern)
5. [AWS API Gateway Authorizers](#slide-05--aws-api-gateway-authorizers)
6. [Cloudflare Access & Workers](#slide-06--cloudflare-access--workers)
7. [Kong · Apigee · Tyk · Krakend](#slide-07--kong--apigee--tyk--krakend)
8. [Rate-Limit-as-Authorisation](#slide-08--rate-limit-as-authorisation)
9. [mTLS Termination & Identity Propagation](#slide-09--mtls-termination--identity-propagation)
10. [JWT Downscoping & Token Exchange](#slide-10--jwt-downscoping--token-exchange-at-the-edge)
11. [WAF vs AuthZ — Knowing the Boundary](#slide-11--waf-vs-authz--knowing-the-boundary)
12. [GraphQL Gateway Patterns](#slide-12--graphql-gateway-patterns)
13. [Webhook Authorisation](#slide-13--webhook-authorisation--signed-payloads--replay)
14. [MCP Gateway — The AI-Era Edge AuthZ](#slide-14--mcp-gateway-revisited--the-ai-era-edge-authz)
15. [Multi-Tenant Edge — Routing & Header Injection](#slide-15--multi-tenant-edge--routing--header-injection)
16. [Observability](#slide-16--observability--latency-deny-rates-attack-signatures)
17. [Anti-Patterns](#slide-17--anti-patterns)
18. [Choosing a Stack](#slide-18--choosing-a-stack)
19. [Summary & References](#slide-19--summary--references)

---

## Slide 01 — Topics

### Where the edge sits
- Edge vs in-app authz — what each does best
- Token validation at the edge — JWT vs introspection
- The Envoy `ext_authz` pattern
- mTLS termination & identity propagation

### Concrete platforms
- AWS API Gateway authorizers
- Cloudflare Access / Workers
- Kong, Apigee, Tyk, Krakend
- Identity-aware proxies — IAP, BeyondCorp lineage

### Patterns
- Rate-limit-as-authorisation
- JWT downscoping & Token Exchange at the edge
- WAF vs AuthZ — knowing the boundary
- GraphQL gateway patterns
- Webhook authorisation
- Multi-tenant edge

### Operational
- MCP Gateway revisited as edge authz
- Observability
- Anti-patterns
- Choosing a stack

---

## Slide 02 — Where the Edge Sits — vs In-App AuthZ

```
[ Client ] → [ EDGE: CDN / CF Access / API Gateway ] → [ MESH / GATEWAY: Envoy / Istio / Linkerd ] → [ APP: in-process PEP, OPA, Cedar ]
                            ↑                                          ↑                                       ↑
                       THIS DECK                            Workload AuthZ deck                 Authorization Models deck
```

Each layer is best at different rules. Don't try to push everything to the edge — and don't leave the edge bare.

### Edge is best at
Coarse-grained checks, rate-limiting, attack mitigation, token-format validation, geofencing — anything that should drop the request *before* it costs your origin a CPU cycle.

### Mesh / gateway is best at
Workload-to-workload identity (mTLS), service-level authz, per-route policy bound to namespaces.

### App is best at
Per-object decisions ("can Alice edit doc 42?"). The edge can't do this — it doesn't know your data model.

---

## Slide 03 — Token Validation at the Edge — JWT vs Introspection

### JWT validation (offline)
- Edge holds the IdP's JWKS in memory; verifies the signature locally.
- Sub-millisecond per token; scales horizontally trivially.
- Works offline (after the JWKS is fetched).
- **Can't revoke before expiry** — a stolen token is valid until `exp`.
- Mitigation: keep `exp` short (5–15 min); rely on refresh-token rotation at the IdP.

### Introspection (online)
- Edge calls the IdP's `/introspect` with the token; IdP returns active=true/false plus claims.
- Revocation is instant.
- **Adds 5–30 ms per request**; scales with the IdP's capacity.
- Useful for opaque tokens (no signature to verify).

### The hybrid pattern most real edges use

1. Validate the JWT signature locally (JWKS).
2. Cache the introspection result for the JTI for some short TTL (~30 s).
3. If the cache misses or the token's TTL is > 5 min, call introspection.
4. On revocation event from the IdP (CAEP / SSF push), invalidate the cache key.

Best of both: 99 % of requests get the offline-fast path; high-value ones get the online check; revocation propagates within seconds.

### Stop logging the token

Strip `Authorization` at the proxy; log only `sub` + a hash if you need correlation.

### JWKS caching

Cache 5–60 minutes; refresh aggressively on unknown `kid`; fall back to the previous JWKS for one rotation cycle to survive issuer key roll.

---

## Slide 04 — The Envoy `ext_authz` Pattern

Envoy is the data-plane underneath most modern edges and meshes. Its `ext_authz` filter is the canonical way to delegate authz to a separate service.

```
[ Client ] ──1.request──▶ [ Envoy ]      ──3.allow + headers──▶ [ Upstream service ]
                            │   ▲
                            │   │ decision
                            ▼   │
                          [ ext_authz service ]   (OPA / custom / Cedar)
                          2. CheckRequest (gRPC)
```

ext_authz can also *add headers* to the request — propagate `X-User-Sub`, `X-Tenant-ID`, downscoped tokens.

### A typical Envoy filter config

```yaml
http_filters:
  - name: envoy.filters.http.ext_authz
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
      transport_api_version: V3
      grpc_service:
        envoy_grpc: { cluster_name: ext_authz }
        timeout: 0.25s
      failure_mode_allow: false   # fail-closed
      include_peer_certificate: true
      with_request_body:
        max_request_bytes: 8192
        allow_partial_message: true
```

### Typical authz services

- **OPA** — built-in `envoy_ext_authz_grpc` server.
- **Custom Go/Rust service** — for bespoke logic + cache.
- **Cedar gRPC wrapper** — newer pattern using AWS Verified Permissions.

### Failure mode is policy

If the authz service is unreachable, does Envoy let the request through (`failure_mode_allow: true`) or block it? The "right" answer depends on whether you'd rather have an outage or a security incident.

---

## Slide 05 — AWS API Gateway Authorizers

| Type | Use |
|---|---|
| **IAM** | Caller signs request with SigV4. |
| **JWT (HTTP API)** | API Gateway validates JWTs against an OIDC issuer's JWKS. Sub-ms. |
| **Lambda authorizer (REQUEST)** | Custom Lambda decides; can read headers, body, source IP. |
| **Lambda authorizer (TOKEN)** | Same as REQUEST but only sees the `Authorization` header. |
| **Cognito user-pool** | Built-in for tenants who use Cognito as the IdP. |

### Lambda authorizer caching

API Gateway can cache the Lambda authorizer's IAM-policy output by a chosen key (token, or token+method, or token+request). 5 min default; up to 1 hour. Saves the Lambda invocation cost on hot paths but caps revocation latency at the TTL.

### A REQUEST Lambda returning a policy

```python
def handler(event, context):
    token = event['headers']['authorization'].split()[1]
    user  = verify_jwt(token, jwks_cache)
    return {
      'principalId': user['sub'],
      'policyDocument': {
        'Version': '2012-10-17',
        'Statement': [{
          'Effect': 'Allow',
          'Action': 'execute-api:Invoke',
          'Resource': event['methodArn']
        }]
      },
      'context': {                # passed to backend as headers
        'sub':       user['sub'],
        'tenant_id': user['tenant_id'],
        'scope':     ' '.join(user['scope'])
      }
    }
```

### REST vs HTTP API

REST API is older, more features, more expensive. HTTP API is newer, leaner, much cheaper, has the built-in JWT authorizer. **Pick HTTP API unless you genuinely need REST features.**

---

## Slide 06 — Cloudflare Access & Workers

### Cloudflare Access — IAP for everything

- Protects an HTTP origin (or self-hosted app via Cloudflare Tunnel) behind a chosen IdP.
- User hits app URL; CF Access redirects to OIDC/SAML; on success issues a CF JWT cookie.
- Origin only sees requests bearing a valid CF JWT (with `email`, `sub`, `groups`).
- Works for unmodified legacy apps — no app code change.
- Free tier (50 users); commercial tier integrates with Okta/Entra/Google + posture signals.

### Validation at the origin

```js
const token = req.headers['cf-access-jwt-assertion'];
const claims = await verifyJwt(token,
  'https://<team>.cloudflareaccess.com/cdn-cgi/access/certs');
require(claims.aud === MY_AUD);
req.user = { sub: claims.sub, email: claims.email };
```

### Cloudflare Workers — programmable edge

- Edge compute on every PoP (~ 300+ cities).
- Run authz logic *before* the request reaches your origin.
- Workers KV / D1 / Durable Objects for state (token revocation list, per-tenant policy).
- ~10 ms cold start; ~1 ms warm.

### A typical Worker

```js
export default {
  async fetch(req, env) {
    const t = req.headers.get('authorization')?.split(' ')[1];
    const claims = await verifyJwt(t, env.JWKS_URL);
    if (!claims || !claims.scope.includes('api:read'))
      return new Response('forbidden', { status: 403 });

    const headers = new Headers(req.headers);
    headers.set('x-user-sub',  claims.sub);
    headers.set('x-tenant',    claims.tenant_id);
    headers.delete('authorization');   // strip before origin

    return fetch(req.url, { method: req.method, body: req.body, headers });
  }
}
```

---

## Slide 07 — Kong · Apigee · Tyk · Krakend

| Gateway | Engine | Auth plugins | Sweet spot |
|---|---|---|---|
| **Kong** | Nginx + Lua / Wasm; OSS & commercial | JWT, OAuth introspection, OIDC, mTLS, key-auth, ACL, OPA plugin | K8s-native; strong plugin ecosystem; popular self-host |
| **Apigee** | Google-managed | OAuth, OIDC, SAML, API key, custom JS / Java callouts | Enterprise-grade; deep analytics; expensive |
| **Tyk** | Go; OSS & cloud | JWT, OAuth, OIDC, key-auth, mTLS | Smaller-team alternative to Kong; good for self-host |
| **Krakend** | Go; OSS & commercial | JWT, OAuth introspection, mTLS, OPA | API *aggregation* (one inbound request fans out); pairs well with stateless JWT |
| **Envoy + Istio Gateway** | Envoy | JWT (RequestAuthentication), ext_authz, mTLS, RBAC | If you're already on Istio mesh |
| **AWS / GCP / Azure managed** | Cloud-managed | Native IdP integrations | Lowest-ops if you're cloud-native |

### A Kong route with JWT + ACL plugins

```yaml
routes:
  - name:    payments
    paths:   ["/v1/payments"]
    methods: ["POST"]
    plugins:
      - name: jwt
        config: { secret_is_base64: false }
      - name: acl
        config: { allow: ["payments-writer"] }
      - name: rate-limiting
        config: { minute: 60, policy: redis, redis_host: rl.svc }
```

### Choosing

- Already on K8s? — Kong / Tyk / Envoy via Istio Gateway.
- Already on a hyperscaler? — managed first, escape if needed.
- Need API *aggregation*? — Krakend.
- Enterprise scale + analytics? — Apigee.

---

## Slide 08 — Rate-Limit-as-Authorisation

Most rate-limit configurations are de-facto authorisation policies — "*this caller may do **at most** this many requests per minute*". Treating them as such (and enforcing at the edge) is one of the highest-leverage pieces of authz you can ship.

### The four common keys

- **Per-IP** — easiest, weakest. Botnets defeat it.
- **Per-API-key** — for partner / B2B traffic.
- **Per-user-sub** — for authenticated traffic. Works because the user's `sub` is signed.
- **Per-tenant** — for multi-tenant SaaS, often combined with per-tier (free / pro / enterprise).

### Stacked limits

```
# per-tenant ceiling
- key: req.headers["x-tenant-id"]
  limit: 10000/min

# per-user inside a tenant
- key: req.jwt.claims.sub
  limit: 600/min

# per-route ceiling
- key: req.method + req.path
  limit: 5000/min
```

Run all three; the *most-restrictive* wins.

### Sliding window vs token bucket

- **Token bucket** — refills at rate R, allows bursts up to B. Forgiving of brief spikes; the default for most consumer APIs.
- **Sliding window** — strict X requests in the last 60 s. Stricter; fairer; preferred for billing-tier limits.
- **Concurrency limit** — at most N in-flight per key. Useful for long-lived requests (LLM inference).

### Communicating limits to clients

- Headers: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`.
- On 429: `Retry-After` header + a JSON body explaining the limit hit (per-tenant? per-user? per-route?).
- Don't 429 silently — clients won't back off if they don't know why.

### Anti-pattern

Rate-limit per-IP only when your traffic is mostly authenticated. A small tenant gets crushed by a noisy neighbour on the same NAT.

---

## Slide 09 — mTLS Termination & Identity Propagation

### The pattern

1. Client presents a client certificate (or DPoP-bound token) at the edge.
2. Edge terminates TLS, validates the cert against a configured CA / trust bundle.
3. Edge extracts the cert's identity (CN, SAN, SPIFFE ID) and injects it as a header for the upstream.
4. Upstream services trust the header — but only because they trust the edge as the issuer.

### A typical header injection

```
# nginx
proxy_set_header X-Client-DN     $ssl_client_s_dn;
proxy_set_header X-Client-CN     $ssl_client_s_dn_cn;
proxy_set_header X-Client-Verify $ssl_client_verify;
proxy_set_header X-Client-Cert   $ssl_client_escaped_cert;

# Envoy with forward_client_cert_details: SANITIZE_SET
http_connection_manager:
  forward_client_cert_details: SANITIZE_SET
  set_current_client_cert_details:
    subject: true
    uri:     true   # SPIFFE URI SANs
    cert:    true
```

### The headers MUST be sanitised

- If the client can set `X-Client-DN` directly and the edge doesn't strip it, the upstream is happily trusting the attacker.
- Edge config: *always* strip these headers from the inbound request, then re-inject them with verified values.
- Envoy's `SANITIZE_SET` mode does this automatically.

### SPIFFE URIs at the edge

If you're already issuing SPIFFE SVIDs internally, an edge that inspects the SAN URI of the client cert can give upstreams a SPIFFE ID directly — same identity model end-to-end.

### DPoP-bound tokens at the edge

Same idea, different mechanism. Edge validates the DPoP proof header; replaces the user's bearer with a server-to-server token (token exchange) that proves "request was bound to a key the user holds".

---

## Slide 10 — JWT Downscoping & Token Exchange at the Edge

### Downscoping — the idea

- User's access token has scope `billing:read billing:write payments:refund`.
- This particular request hits a *read-only* endpoint.
- The edge issues a *downscoped* token to the upstream — `billing:read` only.
- If the upstream is compromised, the blast radius of the token it leaks is bounded.

### Mechanisms

- **Token Exchange (RFC 8693)** — edge calls the IdP's `/token` with `grant_type=token-exchange`, requesting a narrower-scope subject token.
- **Macaroons / Biscuit** — capability-style tokens that can be attenuated client-side without calling back to the IdP.
- **Signed internal JWTs** — edge mints its own short-lived JWT with the narrowed scope, signed by an internal key the upstreams trust.

### A token-exchange call at the edge

```
POST /token HTTP/1.1
Host: idp.acme.com
Authorization: Basic base64(edge_client:secret)

grant_type=urn:ietf:params:oauth:grant-type:token-exchange&
subject_token=<user's incoming access token>&
subject_token_type=urn:ietf:params:oauth:token-type:access_token&
audience=https://api-internal/billing-svc&
scope=billing:read
```

Result: a token usable only at `billing-svc` for `billing:read`, with the original user's `sub` preserved and the edge as `act`.

### Watch latency

A token-exchange call per request adds a ~10 ms IdP round-trip. Cache the downscoped token by (user_sub, target_audience, scope) for the original token's TTL minus a safety margin.

---

## Slide 11 — WAF vs AuthZ — Knowing the Boundary

### WAF — pattern-matching security
- OWASP CRS-style rules — block SQLi-looking strings, XSS payloads, suspicious User-Agents.
- IP-reputation lists, geo-blocks.
- Bot management — challenge / Turnstile / hCaptcha.
- DDoS absorption.

### AuthZ — identity-aware decisions
- Validates tokens, enforces scopes, evaluates per-resource policy.
- Reads JWT claims; evaluates against the rule for this route + this user.
- Can downscope, propagate, audit.

### Where they overlap (and why it's confusing)
- **Rate limiting** — both layers do it. WAF for volumetric / pre-auth; authz for per-user / post-auth.
- **Geo-blocking** — WAF level. But "this user is signing in from a forbidden country" is a CAEP / risk-based-auth signal — different layer.
- **Per-route allow-listing** — both can do it. WAF for "this path doesn't exist publicly"; authz for "this user doesn't have the scope".

### A useful rule

If the rule depends on *who* the request is from (a verified identity) it belongs to authz. If it depends only on *what* the request looks like, it's WAF. Don't put "is the JWT valid?" in WAF rules; don't put "block this CIDR" in authz code.

---

## Slide 12 — GraphQL Gateway Patterns

GraphQL collapses many REST endpoints into a single POST. Edge authorisation needs different patterns to keep up.

### Per-field authz
- The same query may select a public field and a privileged one in one round-trip.
- Edge can't enforce easily — it would need to parse the query and walk the AST.
- Practical pattern: enforce in the GraphQL server (resolver-level), with an edge layer that only does coarse "user is authenticated, query depth ≤ N".
- Tools: **graphql-shield**, **@graphql-tools/auth**, custom directives like `@requiresScope`.

### Persisted queries — the edge-friendly answer
- Client sends a *hash*; the edge looks up the registered query.
- Allow-list: the edge rejects any query hash not in its registry.
- Each persisted query can carry pre-computed authz metadata: required scopes, complexity, intended tenant.
- Bonus: smaller payloads, faster parsing.

### Other edge controls for GraphQL
- **Query depth limits** — guard against malicious nested queries.
- **Query complexity scoring** — each field has a cost; sum must be under a budget tied to the user's tier.
- **Introspection toggle** — disable in production for less attack surface.
- **Dataloader-level rate limits** — per-N+1-fanout, not just per-request.

### If you're considering federation
Apollo Router / Wundergraph Cosmo are GraphQL gateways with built-in JWT validation, per-operation policy and persisted query support.

---

## Slide 13 — Webhook Authorisation — Signed Payloads & Replay

Webhooks are the inverse pattern: an external service POSTs to *your* endpoint.

### The standard pattern
- Sender computes `HMAC-SHA256(secret, body)` and sends it in a header (`Stripe-Signature`, `X-Hub-Signature-256`).
- Receiver recomputes and compares using a constant-time function.
- Sender includes a timestamp; receiver rejects events older than ~ 5 minutes (replay protection).
- Receiver records the event ID; rejects duplicates within the replay window.

### Signature verification, in practice

```js
const sig    = req.headers['stripe-signature'];
const ts     = parseTs(sig);
if (Math.abs(now() - ts) > 300) reject();  // replay window

const expected = hmacSha256(SECRET, ts + '.' + req.rawBody);
if (!constantTimeEq(sig.v1, expected)) reject();

if (eventStore.has(req.body.id)) return ok();  // idempotent
eventStore.add(req.body.id);
process(req.body);
```

### Modern alternatives
- **mTLS** — sender presents a cert; great for B2B partners.
- **OIDC-signed webhooks** — sender mints a JWT signed with a published key; receiver validates via JWKS.
- **CloudEvents + JWS** — emerging standard envelope for events with optional JWS signatures.

### Common mistakes
- Verifying against the parsed JSON instead of the raw body. Whitespace differences = wrong HMAC.
- Skipping the timestamp / replay check.
- Storing the webhook secret in app-level env vars accessible to every developer.
- Auto-rotating the secret without telling the sender (every webhook breaks at midnight).

### Idempotency & the receiver contract
Webhooks are at-least-once. Your handler must be idempotent — keyed on the event ID — or you'll double-charge customers when the sender retries.

---

## Slide 14 — MCP Gateway Revisited — The AI-Era Edge AuthZ

### Why MCP Gateway is an edge authz pattern
- An LLM host (Claude Desktop, Cursor, claude.ai) wants to call *n* remote MCP servers.
- Each MCP server has its own OAuth issuer, scope vocabulary, consent UX.
- The Gateway sits at the edge of the host's process — terminates the host's connection, holds the per-server tokens, mints fresh ones, and proxies.
- Conceptually identical to a B2B "API gateway as the OAuth client" pattern.

### What the Gateway does that a generic edge doesn't
- Per-server *OAuth interceptor* — discovers, registers, exchanges code → tokens, refreshes silently.
- Per-server scope filtering — host can ask for any tool, gateway only forwards tools the user consented to.
- Centralised audit — one log of every tool invocation across every MCP server.
- Optional policy overlay — block destructive tools per-tenant, per-time-of-day, per-risk-score.

### A general "agent edge" emerging
- Other vendors (Stytch, WorkOS, Auth0) are shipping similar "agent identity proxies".
- All converge: validate human-user identity, validate agent's identity, mint short-lived downscoped tokens to upstream APIs, audit every action.
- Expect this to be a generic "agent gateway" product category by 2027.

---

## Slide 15 — Multi-Tenant Edge — Routing & Header Injection

### How the edge tells which tenant a request is for
- **Subdomain** — `{tenant}.acme.com`. Easiest. Requires wildcard cert.
- **Path prefix** — `/t/{tenant}/...`. Trivial for proxies; ugly for end users.
- **JWT claim** — `tenant_id` claim in the user's access token. The right answer for B2B SaaS where the user belongs to one tenant.
- **Header from upstream IdP** — IdP injects a tenant claim during sign-in.

### After identification — what flows down

```
# strip everything client-controlled
x-tenant-id:    DELETE
x-user-sub:     DELETE
x-user-scope:   DELETE
x-org-id:       DELETE

# inject from verified sources
x-tenant-id:    {jwt.tenant_id}
x-user-sub:     {jwt.sub}
x-user-scope:   {jwt.scope}
x-request-id:   {edge-generated UUID}
```

### Per-tenant policy at the edge
- Different tenants get different rate limits, IP allow-lists, geo restrictions, scope policies.
- Lookup by tenant_id from a config store (DynamoDB / Workers KV / Consul) at the edge — sub-ms with hot caches.
- Cache invalidation: on tenant config change, push to the edge.

### Tenant isolation traps
- **Trusting client-supplied tenant headers** — always strip then re-inject from a verified source.
- **Caching by URL only** when the URL is identical across tenants. Cache by URL *and* tenant_id.
- **Logging tenant data globally** — if logs land in one Splunk index, your data-residency story is half-true.

---

## Slide 16 — Observability — Latency, Deny Rates, Attack Signatures

### Edge metrics worth wiring up
- **`edge.authz.deny_total{reason}`** — labelled by `invalid_token`, `insufficient_scope`, `rate_limited`, `geo_blocked`.
- **`edge.token.validate.duration_ms`** — quantile per IdP / per JWKS endpoint.
- **`edge.tenant.req_total{tenant_id, route, status}`** — fans out into per-customer dashboards.
- **`edge.upstream.duration_ms`** — to surface "slow because of upstream" vs "slow because of authz".
- **`edge.authz.cache.hit_rate`** — < 95 % means your caching strategy needs work.

### Detection signals
- Spikes in `invalid_token` from a single IP/ASN — credential stuffing or token enumeration.
- Unusual `insufficient_scope` on routes the user has never hit — privilege probing.
- Sudden CAEP / introspection-cache miss spike — a token was revoked at the IdP and 47 services are hitting your edge with it.
- JWKS fetch errors — the edge is about to start failing closed.

### Audit log line — what to include

```json
{
  "ts": "2026-05-06T09:00:01Z",
  "request_id": "abc…",
  "edge_pop":   "lhr01",
  "tenant_id":  "t_42",
  "user_sub":   "u_1234",
  "method":     "POST",
  "path":       "/v1/payments",
  "decision":   "allow",
  "matched_rule": "policy:billing-write@v17",
  "upstream":   "billing-svc.eu-west-1",
  "latency_ms": 4.2
}
```

---

## Slide 17 — Anti-Patterns

- **Trusting client-supplied identity headers** — The edge must *strip and re-inject*.
- **Long-lived JWKS caches** — JWKS cached for > 24 h means key rotation breaks your edge.
- **Default-allow on auth-server outage** — `failure_mode_allow: true` is a footgun. Decide deliberately.
- **Logging Authorization headers** — Tokens end up in CloudWatch / Datadog. Strip at the proxy.
- **Authz code in the WAF, WAF rules in the authz** — Pattern matching belongs to WAF. Identity-aware decisions belong to authz.
- **Per-IP rate limits as the only defence** — Botnets and CGNAT defeat per-IP.
- **Forgetting the OPTIONS / CORS preflight** — Your fancy edge authz blocks the browser's preflight. Allow OPTIONS through unauthenticated.
- **Static API keys as the only auth** — Pair with mTLS / IP allow-list / per-key rate limits.

---

## Slide 18 — Choosing a Stack

| If you're... | Likely best | Why |
|---|---|---|
| Consumer SaaS, global audience | **Cloudflare Access + Workers** | ~300 PoPs; built-in IdP integrations; programmable. |
| Heavily AWS-centric, cost-sensitive | **AWS HTTP API + Lambda authorizers** | Cheap, native IAM glue, JWT authorizer for free. |
| K8s-native, want OSS & plugins | **Kong / Tyk** | K8s ingress controllers, JWT/OIDC plugins, OPA integration. |
| Already on Istio mesh | **Istio Gateway + RequestAuthentication + AuthorizationPolicy** | Same primitives as your mesh. |
| Internal tools / "make every app SSO" | **Cloudflare Access / Pomerium / oauth2-proxy** | Identity-aware proxy in front of unmodified apps. |
| Enterprise scale, deep analytics | **Apigee / Mulesoft** | Established enterprise controls; cost reflects it. |
| API *aggregation* across many backends | **Krakend** | One inbound request fans out, recombines responses. |
| Building / shipping an MCP / agent product | **Docker MCP Gateway** + your usual edge | Specialised edge for agent ↔ MCP-server flows. |

---

## Slide 19 — Summary & References

### What we covered

- Edge vs mesh vs in-app authz — what each layer does best
- Token validation at the edge — JWT vs introspection, the hybrid pattern
- Envoy `ext_authz` — the canonical delegation pattern
- AWS API Gateway authorizers — the four flavours
- Cloudflare Access & Workers
- Kong / Apigee / Tyk / Krakend — per-platform fit
- Rate-limit-as-authorisation
- mTLS termination + identity propagation (and the "sanitise headers" rule)
- JWT downscoping & token exchange at the edge
- WAF vs AuthZ — knowing the boundary
- GraphQL gateway patterns · webhook authorisation
- MCP Gateway as the AI-era edge authz pattern
- Multi-tenant edge · observability · anti-patterns · choosing a stack

### Three take-aways

1. **Don't push everything to the edge.** Coarse decisions belong here; per-object rules belong in the app. Layer them.
2. **Strip then re-inject identity headers.** Anything the upstream reads from `X-User-*` must originate from *your* edge, not the internet.
3. **Treat rate limits as authorisation policy.** They're cheap, effective and most outages would have been smaller if they'd been wired up before launch.

### One-line takeaway

The edge is your cheapest authorisation layer — drop bad requests there, propagate verified identity downstream, and let the app worry about per-object rules.

### References

Envoy `ext_authz` docs · Istio RequestAuthentication / AuthorizationPolicy · AWS API Gateway authorizers · Cloudflare Access & Workers · Kong gateway docs · Apigee policy reference · OWASP API Security Top 10 (2023) · OWASP CRS (WAF) · CloudEvents v1.0 + JWS · Stripe / GitHub webhook signing · Apollo Router / Wundergraph Cosmo · OpenID SSF / CAEP · RFC 6749 / 7519 / 8693 / 9449 / 9700

# 🛡 Edge & Gateway AuthZ

An interactive Reveal.js presentation on **north-south authorisation** — what happens at the edge of your system before a request reaches your service code. Token validation, identity-aware proxies, API gateways, rate-limit-as-policy, JWT downscoping, and the MCP Gateway as the AI-era edge authz pattern.

## ▶ [Open the Presentation](https://brendanjameslynskey.github.io/Edge_and_Gateway_AuthZ/)

## 📄 [Markdown Version](presentation.md)

## 📚 Companion decks — [Authorization Models](https://brendanjameslynskey.github.io/Authorization_Models/) · [Workload Identity & Service-Mesh AuthZ](https://brendanjameslynskey.github.io/Workload_Identity_AuthZ/) · [OAuth for MCP Servers](https://brendanjameslynskey.github.io/OAuth_for_MCP/)

---

## Contents

| # | Topic | Description |
|---|-------|-------------|
| 01 | Title | Validate → Enforce → Propagate → Observe |
| 02 | Topics | Where the edge sits · platforms · patterns · operational |
| 03 | Where the Edge Sits | Edge vs mesh vs in-app — what each layer does best |
| 04 | Token Validation at the Edge | JWT vs introspection; the hybrid pattern; JWKS caching |
| 05 | Envoy `ext_authz` | The canonical delegation pattern; failure-mode policy |
| 06 | AWS API Gateway Authorizers | IAM / JWT / Lambda (REQUEST + TOKEN) / Cognito |
| 07 | Cloudflare Access & Workers | IAP for everything + programmable edge |
| 08 | Kong · Apigee · Tyk · Krakend | Per-platform fit |
| 09 | Rate-Limit-as-Authorisation | Keys, windows, communicating limits |
| 10 | mTLS Termination & Identity Propagation | Sanitise then re-inject; SPIFFE URIs at the edge |
| 11 | JWT Downscoping & Token Exchange | Narrowing scopes per upstream; macaroons / biscuit |
| 12 | WAF vs AuthZ | Knowing the boundary |
| 13 | GraphQL Gateway Patterns | Per-field authz, persisted queries, complexity scoring |
| 14 | Webhook Authorisation | Signed payloads, replay protection, idempotency |
| 15 | MCP Gateway Revisited | The AI-era edge authz pattern |
| 16 | Multi-Tenant Edge | Routing, header injection, per-tenant policy |
| 17 | Observability | Metrics, detection signals, audit log lines |
| 18 | Anti-Patterns | The eight common edge-authz foot-guns |
| 19 | Choosing a Stack | By use case |
| 20 | Summary | Three take-aways and references |

---

## Audience

- Engineers building public APIs and asking "where do I validate the token?".
- Architects choosing between Cloudflare Access / API Gateway / Kong / Istio Gateway.
- Anyone shipping an agent / MCP product who needs to think about edge token flow.
- Platform / SRE teams wiring observability for an existing edge.

This deck is the **north-south complement** to [Workload Identity & Service-Mesh AuthZ](https://github.com/BrendanJamesLynskey/Workload_Identity_AuthZ), which covers east-west service-to-service authz; both build on [Authorization Models](https://github.com/BrendanJamesLynskey/Authorization_Models)' conceptual foundations.

## Slide Controls

| Action | Key |
|--------|-----|
| Next / Previous | `→` `←` or swipe |
| Overview | `Esc` |
| Fullscreen | `F` |
| Export to PDF | Append `?print-pdf` to URL, then print |

## Technology

[Reveal.js 4.6](https://revealjs.com) · [highlight.js](https://highlightjs.org) · Playfair Display + DM Sans + JetBrains Mono · inline SVG diagrams.

Single self-contained `index.html` — no build step, no npm, no dependencies to install.

## See also

- [Authorization Models](https://github.com/BrendanJamesLynskey/Authorization_Models) — RBAC/ABAC/ReBAC/Policy-as-Code foundations.
- [Workload Identity & Service-Mesh AuthZ](https://github.com/BrendanJamesLynskey/Workload_Identity_AuthZ) — east-west service-to-service.
- [OAuth for MCP Servers](https://github.com/BrendanJamesLynskey/OAuth_for_MCP) — the MCP Gateway in detail.
- [Advanced OpenID Connect](https://github.com/BrendanJamesLynskey/Advanced_OpenID_Connect) — Token Exchange, FAPI 2.0 edge requirements.
- [Cloud_aaS_05_Cloud_Security](https://github.com/BrendanJamesLynskey/Cloud_aaS_05_Cloud_Security) — wider cloud-security context.

## References

Envoy `ext_authz` docs · Istio RequestAuthentication / AuthorizationPolicy · AWS API Gateway authorizers · Cloudflare Access & Workers · Kong gateway docs · Apigee policy reference · OWASP API Security Top 10 (2023) · OWASP CRS (WAF) · CloudEvents v1.0 + JWS · Stripe / GitHub webhook signing · Apollo Router / Wundergraph Cosmo · OpenID SSF / CAEP · RFC 6749 / 7519 / 8693 / 9449 / 9700

## License

Educational use. Code examples provided as-is.

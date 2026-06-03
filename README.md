# jupiterstorm-core

Shared platform core for the JupiterStorm ecosystem. An independent Go module providing cross-cutting
**authentication and identity** so multiple products (JupiterStorm, Jupiter Sports Track, …) can share one
auth implementation and one Keycloak realm.

This module is **server-side and auth-only**. It deliberately holds no domain logic and no datastore
dependency — feature logic and persistence live in each product's own repository.

## Charter

- **In scope:** Gin auth middleware, HMAC session signing/verification, OIDC handlers (Keycloak + Google),
  the CLI device-authorization flow, and server-side token exchange.
- **Out of scope:** any feature/domain logic, any database access, any HTTP-client helpers (those belong in
  product SDKs).

Keep dependencies minimal: `gin`, `golang.org/x/oauth2`, and the standard library. Adding a datastore or
feature dependency here is a red flag.

## Package: `auth`

```go
import "github.com/greggtrueb/jupiterstorm-core/auth"
```

| Symbol | Purpose |
|---|---|
| `NewHandler(...)` / `(*Handler)` | Google OAuth2 login, callback, logout |
| `NewKeycloakHandler(...)` / `(*KeycloakHandler)` | Keycloak OIDC login, callback, logout, device flow, token exchange |
| `RequireSession(sessionSecret string, authDisabled bool) gin.HandlerFunc` | Validates the signed session (cookie or `Authorization: Bearer`) and sets identity in the Gin context |
| `RequireRole(roles ...string) gin.HandlerFunc` | Restricts a route to the given roles; must run after `RequireSession` |

### Integration contract

`RequireSession` sets three keys on the Gin context, which consuming handlers read:

- `userEmail` — authenticated user's email
- `userName` — display name
- `userRole` — one of `admin`, `manager`, `staff`

These keys are the stable public interface between core and any product. Treat them as frozen.

### Cross-product identity

Sessions are stateless: a signed token is an HMAC over `SESSION_SECRET` carrying `email|name|role` plus a
timestamp — no database lookup on the request path. Two products that share the same `SESSION_SECRET` and
Keycloak realm will validate each other's sessions with no network call. This is the intended mechanism for
a second product to reuse JupiterStorm identity.

`AUTH_DISABLED=true` makes `RequireSession` pass every request through as a fixed dev identity
(`dev@local`, role `admin`). Never set this in production.

## Development

```sh
make build   # go build ./...
make vet     # go vet ./...
make test    # go test -race ./...
make pre-push
```

Consumers may use a local `replace` directive during development:

```
replace github.com/greggtrueb/jupiterstorm-core => ../jupiterstorm-core
```

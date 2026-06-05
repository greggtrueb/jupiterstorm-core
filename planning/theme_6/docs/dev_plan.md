# jupiterstorm-core — Theme 6 Development Plan

**Repository:** `github.com/greggtrueb/jupiterstorm-core`
**Theme:** Notifications → introduces the shared **Notification Delivery** core capability
**Version:** 0.1 — Draft
**Last Updated:** 2026-06-05
**Owner:** ___________

---

## Status Key

| Status | Meaning |
|---|---|
| `NOT STARTED` | Work has not begun |
| `IN PROGRESS` | Actively being worked on |
| `IN REVIEW` | Complete, awaiting sign-off |
| `DONE` | Accepted and merged |

---

## Purpose

Theme 6 adds **notification delivery** to `jupiterstorm-core` — the **third** cross-cutting capability,
after `auth` (Theme 2) and `tasks` (Theme 5). Core delivers messages over channels (email first; Slack/SMS
later) behind an interface; it holds **no domain logic and no storage**. Deciding *what* to send, *to whom*,
*when*, and keeping an in-app inbox is the **product's** job (see the API Theme 6 plan).

This keeps the core charter intact (infrastructure vs. domain — see Theme 2): `notify` moves messages, just
as `tasks` moves jobs and `auth` moves sessions.

### Relationship to other repos & capabilities

- **Consumes the Theme 5 `tasks` engine** — the product enqueues a `notify:send` job and a worker calls
  `notify` to deliver, so a slow/failed email never blocks a request and gets the task engine's retries.
- **`jupiter-infra`** provides the email transport (SMTP relay / provider creds). See its Theme 6 plan.
- **JupiterStorm API** is the first consumer. See the API Theme 6 plan.

---

## Phase 1 — `notify` package

### Interfaces (IDD)

```go
package notify

import "context"

// Channel delivers a single message over one transport (email, Slack, SMS, …).
type Channel interface {
    // Name returns the channel identifier ("email", "slack", …).
    Name() string
    Send(ctx context.Context, m Message) error
}

// Message is a channel-agnostic notification payload. The product renders the
// title/body; core only delivers. Recipient is interpreted per channel
// (an email address for email, a user/handle for chat, etc.).
type Message struct {
    Recipient string            // channel-specific address
    Title     string            // subject line / heading
    Body      string            // plain-text body
    HTMLBody  string            // optional HTML alternative (email)
    Meta      map[string]string // optional channel hints (cc, link, …)
}

// Dispatcher routes a message to a registered channel by name.
type Dispatcher interface {
    Register(c Channel)
    Send(ctx context.Context, channel string, m Message) error // ErrUnknownChannel if not registered
}
```

### Implementations

- [ ] `notify/dispatcher.go` — a default `Dispatcher` (channel-name → `Channel` map); `ErrUnknownChannel`
- [ ] `notify/email.go` — `EmailChannel` implementing `Channel` over SMTP. Config struct (host, port, from,
      auth) passed in — sourced from env by the consumer, transport provisioned by `jupiter-infra`. Uses
      stdlib `net/smtp` (or a thin, well-maintained SMTP lib); supports plain-text + optional HTML.
- [ ] `notify/memory.go` — an in-memory `Channel`/`Dispatcher` that records sent messages, so consumers can
      unit-test "a notification was sent" without a real SMTP server

### Async note

`notify` itself is synchronous (`Send` blocks until the channel returns). Asynchrony is the consumer's
choice via the `tasks` engine: the API enqueues a `notify:send` job whose handler calls the dispatcher.
Core does not couple the two — it just provides the delivery primitive.

### Tasks

- [ ] Define `Channel`, `Message`, `Dispatcher`
- [ ] `EmailChannel` (SMTP) + config
- [ ] in-memory channel/dispatcher for tests
- [ ] Unit tests: dispatch routing, unknown-channel error, email rendering (against a fake SMTP / recorder)
- [ ] README: document the `notify` capability; channels are pluggable, recipients are channel-specific
- [ ] Keep dependencies tight — SMTP only; no domain packages

### Definition of Done

- A consumer can register an `EmailChannel` and `Dispatcher.Send(ctx, "email", msg)` to deliver email
- Adding a `SlackChannel` / `SMSChannel` later is a new `Channel` behind the same interface — no consumer change
- Tests use the in-memory channel; no SMTP dependency
- No domain logic or storage enters core

---

## Future channels (behind the interface — not Phase 1)

- `SlackChannel`, `SMSChannel` (Twilio), push — each a new `Channel`; the product opts users into them via
  preferences. Tracked in the API Theme 6 plan / backlog.

---

## Document Changelog

| Version | Date | Summary | Author |
|---|---|---|---|
| 0.1 | 2026-06-05 | Initial plan — add a generic, interface-driven **notification delivery** capability (`notify` package): `Channel`/`Message`/`Dispatcher`, an SMTP `EmailChannel`, and an in-memory channel for tests. Third core capability after `auth` and `tasks`; async via the `tasks` engine; reusable by any product. | — |

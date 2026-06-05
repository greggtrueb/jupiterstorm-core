# jupiterstorm-core — Theme 5 Development Plan

**Repository:** `github.com/greggtrueb/jupiterstorm-core`
**Theme:** Bulk Data Entry → introduces the shared **Task Engine** core capability
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

Theme 5's invoice OCR needs asynchronous background processing. Rather than build a one-off queue in the
API, the **generic task engine** is added to `jupiterstorm-core` so it becomes a **shared platform
capability** — the second after auth — usable by any product (JupiterStorm, Jupiter Sports Track) for any
background work, not just invoices.

It is **interface-driven (IDD)**: products depend on the core interfaces, never on the queue technology.
The v1 implementation is **asynq** (Redis-backed), but a different backend (e.g. River/Postgres) can be
dropped in later behind the same interfaces with no consumer change.

This fits the core charter (cross-cutting infrastructure, no domain logic) — see the API's Theme 2
(Platform Core) plan. Job *types* and their payloads are defined by **consumers**, not by core; core only
moves opaque jobs.

### Relationship to other repos

- **`jupiter-infra`** provisions Redis (the asynq broker) and the asynq monitoring dashboard. See its
  Theme 5 plan.
- **JupiterStorm API** is the first consumer: it enqueues `invoice:parse` and runs a `Worker` in
  `cmd/invoice-worker`. See the API Theme 5 plan, Phase 2.

---

## Phase 1 — Task Engine (`tasks` package)

### Interfaces (the public contract — IDD)

```go
package tasks

import "context"

// Enqueuer hands a job off for asynchronous processing. typ names the job kind
// (consumer-defined, e.g. "invoice:parse"); payload is opaque bytes the handler
// for that type knows how to decode.
type Enqueuer interface {
    Enqueue(ctx context.Context, typ string, payload []byte, opts ...Option) (JobID, error)
}

// Handler processes one job of a single type.
type Handler interface {
    Handle(ctx context.Context, payload []byte) error
}

// Worker registers handlers by type and runs the processing loop until ctx is
// cancelled. A returned error from a handler triggers the backend's retry policy.
type Worker interface {
    Register(typ string, h Handler)
    Run(ctx context.Context) error
}

type JobID string

// Option tunes a single enqueue (queue name, max retries, delay, dedup key).
// Implemented opaquely so the option set can grow without breaking callers.
type Option func(*enqueueConfig)

func Queue(name string) Option       // route to a named queue/priority
func MaxRetries(n int) Option        // backend retry budget
func Delay(d time.Duration) Option   // process-not-before
func Unique(key string) Option       // best-effort dedup within a window
```

### asynq implementation (v1 backend)

- [ ] `tasks/asynq.go` — `AsynqEnqueuer` wrapping `asynq.Client`, `AsynqWorker` wrapping `asynq.Server` +
      `asynq.ServeMux`. `Option`s map onto `asynq.Option`s.
- [ ] `NewAsynqEnqueuer(redis RedisConfig) (*AsynqEnqueuer, error)` and
      `NewAsynqWorker(redis RedisConfig, opts WorkerConfig) *AsynqWorker` — Redis connection details are
      passed in (sourced from env by the consuming binary; provisioned by `jupiter-infra`)
- [ ] `RedisConfig` (addr, password, db) — a small config struct, not a global

### In-memory implementation (for consumer tests)

- [ ] `tasks/memory.go` — `MemoryQueue` implementing both `Enqueuer` and `Worker` synchronously (or via a
      goroutine), so a consumer (e.g. the API invoice handler/worker) can unit-test enqueue + handle without
      Redis

### Tasks

- [ ] Define the `tasks` package interfaces + `Option`s above
- [ ] asynq-backed `Enqueuer`/`Worker`
- [ ] in-memory `Enqueuer`/`Worker` for tests
- [ ] Unit tests: round-trip a job through the in-memory impl; asynq wiring smoke-tested behind a build tag
      or with a miniredis fake
- [ ] README: document the `tasks` capability + that job types/payloads are consumer-defined
- [ ] Keep dependencies tight — `tasks` may pull in `asynq` + Redis client, but no domain packages

### Definition of Done

- A consumer can `Enqueue(ctx, "some:type", payload)` and run a `Worker` that dispatches to a registered
  handler — against asynq in production and the in-memory impl in tests
- Swapping the backend is an implementation change behind unchanged interfaces
- No domain logic enters core; job types remain consumer-defined

---

## Notes for the core charter

The task engine is core's **second** cross-cutting capability after `auth`. Like auth, it is infrastructure
(moving opaque work), holds no product/domain logic, and is consumed via interfaces. This is a deliberate,
charter-consistent expansion — not scope creep — and should be reflected in the Theme 2 (Platform Core)
charter when that plan is next revised.

---

## Document Changelog

| Version | Date | Summary | Author |
|---|---|---|---|
| 0.1 | 2026-06-05 | Initial plan — add a generic, interface-driven **task engine** (`tasks` package) to core: `Enqueuer`/`Handler`/`Worker` interfaces, an **asynq** (Redis) backend, and an in-memory backend for tests. Driven by Theme 5 invoice OCR; reusable by any product. | — |

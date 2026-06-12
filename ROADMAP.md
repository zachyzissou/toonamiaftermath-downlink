# Toonami Aftermath Downlink Roadmap

Last refreshed: 2026-05-31T05:48Z

## Current Truth

- Canonical GitHub Project: [#42 toonamiaftermath-downlink](https://github.com/users/zachyzissou/projects/42)
- Repo state: production-maintained IPTV feed generation service with Python backend, browser control panel, Docker/Unraid deployment, and test coverage.
- Open repo issue: `#40`
- Open repo PRs: `#42`, `#43`, `#44`
- Current planning lane: raise operator trust/resilience from the UX review baseline while keeping dependency and license maintenance visible.

## Active Gates

| Gate | Tracking | Status | Next Action | Done Criteria |
| --- | --- | --- | --- | --- |
| UX trust floor | `#40` | Ready | Implement P0 remediation for CSP, refresh-lock UX, and first-run empty-state guidance. | CSP is present, refresh no longer feels frozen, first-run path is explicit, and validation evidence is posted to `#40`. |
| Python formatter security update | `#42` | In review | Review black `24.10.0` to `26.3.1` update and confirm lint/test behavior remains stable. | PR checks pass and dependency update is merged or closed with a stated reason. |
| Node dependency security update | `#43` | In review | Review flatted `3.3.3` to `3.4.2` update. | PR checks pass and dependency update is merged or closed with a stated reason. |
| Licensing posture | `#44` | In review | Decide whether the restrictive source-visible license change is the intended distribution model. | License PR is merged with README notice aligned, or closed with the retained license documented. |

## Implementation Sequence

1. Ship the P0 UX stabilization from `#40`.
2. Resolve dependency PRs `#42` and `#43` after checks and compatibility review.
3. Resolve license PR `#44` before any broader distribution or packaging change.
4. Add P1 UX resilience work: non-blocking refresh, better failure transparency, accessibility labels.
5. Add P2 guardrails: dashboard lifecycle state model and CI coverage for refresh/onboarding/error states.

## Out Of Scope For This Roadmap

- Feed-provider scraping changes without separate parser evidence.
- Credential format changes without migration notes.
- Generated `/data` artifacts or production credentials in git.
- Docker/Unraid deployment changes without rollback notes.

## Review Checklist

- Run Python tests touched by the change, normally `python test_logic.py`, `python test_integration.py`, and `python test_frontend.py`.
- Run frontend lint/checks when web assets change.
- Keep README current truth and Project #42 aligned when new active gates are opened.
- Redact credentials, feed URLs, tokens, and generated user secrets from issues and PR evidence.

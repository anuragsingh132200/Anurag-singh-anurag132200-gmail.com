# DECISIONS

One section per decision that a reviewer might reasonably have made differently. Every section has
the same four parts, and the third and fourth are the ones we weigh most.

Rules, from `DISCOVERY-BRIEF.md`:

- cite something real in `Why` — a commit, a test, an error string, a file and line
- do not restate what a document says; describe what you did when the documents ran out
- six to twelve decisions is the expected range

---

### Org-level resolution includes device-scoped grants

**What I chose:** A null device context resolves the union of org-wide and device grants.
**Why:** The UI navigation represents authority held anywhere in the org, while exact device rows
still resolve against one id (`BUILD-LOG.md`, Phase 2; `check-permissions.js`, D6 cases).
**What I rejected:** Treating null as “org-wide grants only”; it loses device-scoped authority
from the org-level effective set.
**What would change my mind:** A contract defining org-level resolution as intersection or as an
org-only scope rather than a union.

### Database constraints arbitrate exclusive sessions and unknown permissions

**What I chose:** Insert directly and translate the two relevant SQLite constraint failures.
**Why:** `one_exclusive_session_per_device` and the `grant_permissions` foreign key remain correct
under concurrent writers; the API suite observes `DEVICE_BUSY` and `unknown_permission`.
**What I rejected:** Check-then-insert validation, which introduces a race between the check and
the write and duplicates the catalogue.
**What would change my mind:** Moving to storage without equivalent transactional constraints.

### Owners may modify another owner when last-owner protection remains satisfied

**What I chose:** Permit owner-to-owner modification, then independently enforce `LAST_OWNER`.
**Why:** My literal equal-rank rejection failed the public “demoting a NON-last owner is allowed”
case (BUILD-LOG.md, Phase 3).
**What I rejected:** A blanket equal-rank refusal; it makes the tested non-last-owner transition
impossible.
**What would change my mind:** A clarified contract that removes that public case or introduces a
separate ownership-transfer operation.

---

## Where this repo argues with itself

`PERMISSIONS.md` says a caller may modify only a “strictly lower role,” but `check-api.js` expects
one owner to demote another non-last owner. I built against the executable contract and kept the
last-owner invariant as the safety boundary.

Building against the written rule and arguing in writing is a **full-marks** answer. Silently
working around it, or quietly picking one and saying nothing, scores zero on the section — we
cannot tell the difference between a decision and an oversight.

## Deliberately not built

What you chose not to build, and the reason. A scope cut with a stated reason is a senior
judgement. An unmentioned gap is a gap.

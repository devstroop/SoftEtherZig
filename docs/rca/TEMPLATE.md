# RCA Template — Subsystem Name

> **Date:** YYYY-MM-DD  
> **Author:**  
> **Status:** Draft | Final | Superseded  
> **Supersedes:** (optional — link to previous RCA if updating)

---

## Executive Summary

One-paragraph description of the issue: what broke, what the impact was, and how it was fixed.

---

## Architecture Context

Describe how this subsystem fits into the overall system. Include a brief ASCII diagram if helpful. Reference the data flow and which other subsystems interact with this one.

---

## Root Cause

Describe the root cause in detail. Include:

- **The buggy code path** (file:line references)
- **Why it worked before** (if a regression)
- **Why it broke now** (what changed)
- **The failure mode** (what the user experiences)

---

## Detection

How was this issue found? Include:

- Log patterns or DIAG metrics that indicate the problem
- Symptoms in speedtest results
- How to reproduce

---

## Fix Applied

Describe the exact code change. Include before/after snippets. Reference the commit hash if committed.

---

## Why It Regressed (if applicable)

If this was a regression from working code, explain what change introduced it and why the earlier code was correct.

---

## Lesson Learned

What general principle should be derived from this fix? (e.g., "Never fork/exec in the event loop", "OpenSSL WANT_WRITE must retry with same buffer")

---

## Prevention Checklist

Specific, actionable items that, if followed, would prevent this class of bug:

- [ ] Item 1
- [ ] Item 2
- [ ] Item 3

---

## References

- Related source files with line numbers
- Related RCAs (cross-reference)
- External documentation (RFCs, OpenSSL docs, Apple documentation)
- Git commits (this fix, introduction of bug)

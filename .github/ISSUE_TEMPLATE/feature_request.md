---
name: Feature Request
about: Suggest a new feature or enhancement for libsoftether
labels: ["enhancement"]
---

## Problem

What problem does this feature solve? Is it related to a limitation, workaround, or missing capability?

## Proposed Solution

Describe what you'd like to see. Include API sketches if relevant:

```zig
// Example: new setter function
export fn softether_set_new_option(client: ?*VpnClient, value: bool) void { ... }
```

## Alternatives Considered

Any workarounds or alternative approaches you've tried.

## Platform Scope

Which platforms should this target?

- [ ] All (C ABI — FFI consumers)
- [ ] CLI (`vpnclient`)
- [ ] Flutter / Dart FFI bindings
- [ ] Specific platforms only: `...`

## Additional Context

Links to related issues, SoftEther documentation, or protocol specs.

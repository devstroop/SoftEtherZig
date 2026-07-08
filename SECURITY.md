# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.3.x   | ✅ |
| 0.2.x   | ✅ |
| < 0.2   | ❌ |

## Reporting a Vulnerability

If you discover a security vulnerability in libsoftether, **do not open a public issue.** Instead:

1. **Email** the maintainer directly at the address listed in the [GitHub repo's About section](https://github.com/devstroop/SoftEtherZig).
2. Include:
   - Description of the vulnerability
   - Steps to reproduce (build command + payload if applicable)
   - Affected platform(s) and Zig version
   - Any proposed fix (if you have one)

### What to expect

| Stage | Timeline |
|-------|----------|
| Acknowledgment | Within 48 hours |
| Triage & initial assessment | Within 1 week |
| Fix released | Depends on severity — critical fixes within days, moderate within 2 weeks |

### Scope

The following are **in scope**:
- Memory safety issues (buffer overflows, use-after-free, double-free)
- Authentication bypass or credential leakage via the C ABI
- TLS/SSL handshake vulnerabilities (certificate validation bypass, downgrade attacks)
- Denial-of-service via malformed Pack serialization
- Arbitrary code execution through FFI input validation failures

The following are **out of scope**:
- Issues in the upstream SoftEther VPN Server (report to [SoftEther](https://www.softether.org/))
- Issues in system OpenSSL (report to your OS vendor)
- Bugs that require physical access to the victim's machine
- Social engineering attacks

## Disclosure Policy

We follow coordinated disclosure. Please give us reasonable time to fix the issue before disclosing it publicly. We will credit reporters in the release notes unless anonymity is requested.

# OTP Password-Recovery Specification

A language-agnostic, framework-agnostic specification for a secure **OTP-based "Forgot Password" flow**. It is written so that both developers and AI coding tools can implement and review it.

**Full specification:** [`otp-password-recovery-spec.md`](./otp-password-recovery-spec.md)

## The flow

1. **Request recovery:** the user submits an email and gets a generic response.
2. **Issue a code:** a one-time code is generated, stored as a verifier, and sent to the registered email.
3. **Verify the code:** limited attempts, short expiry, atomic single use.
4. **Issue a reset token:** short-lived, single-use, valid only for changing the password.
5. **Set the new password:** the token is consumed atomically.
6. **Finish:** old sessions are revoked, the user is notified, and the user signs in normally.

## What the specification covers

- **Requirements:** MUST/SHOULD rules with stable IDs (`OTP-xx`, `VER-xx`, `TOK-xx`, `POST-xx`, `FLOW-xx`)
- **Threat-to-control map:** which requirement defends against which attack
- **AI-tool guidance:** how a coding assistant should plan, implement, and report
- **Acceptance tests:** 19 security-focused scenarios
- **Checklist:** a one-page review list

## Threats addressed

Duplicate valid codes · email/SMS spam · user enumeration · brute force · replay · race conditions · leaked storage and logs · cross-purpose code reuse · surviving attacker sessions · client-side flow skipping

## Example defaults

These values are examples, not mandates. Make them configurable.

| Setting | Example |
|---|---|
| Code length | 6 digits |
| Code lifetime | 5 minutes |
| Resend cooldown | 60 seconds |
| Max verification attempts | 5 |

## Using it with AI coding tools

Point the tool at the specification file and ask it to produce a plan first. The specification's AI-tool guidance section covers what to inspect, what to avoid assuming, and which tests to run and report.

## References

- [OWASP Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)
- [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html)

# OTP-Based Password Recovery — System Specification (for AI tools)

## 0. How to use this document

- This is a **language-agnostic, framework-agnostic specification** of a secure OTP-based "Forgot Password" flow.
- Requirements use **MUST / MUST NOT / SHOULD**. MUST is mandatory for a correct implementation.
- Numeric values (6 digits, 5 attempts, 5 minutes, 60 seconds) are **example defaults**, not standards-mandated. They SHOULD be configurable and documented.
- Each requirement has an ID (e.g. `OTP-07`) so it can be referenced in plans, reviews, and tests.

## 1. Goal and scope

Let a user who forgot their password prove control of the email address already associated with their account using a short-lived, single-use code, then set a new password. The design must resist: duplicate valid codes, spam/abuse, user enumeration, brute force, replay, race conditions, leaked storage or logs, cross-purpose code reuse, and attacker sessions that survive the reset.

**Scope limit:** an emailed recovery code proves access to a mailbox. It is **not** strong multi-factor authentication. NIST SP 800-63B does not permit email as an out-of-band authenticator for authentication. Do not reuse this flow as a login second factor. For high-assurance accounts, consider stronger recovery methods.

## 2. Terminology

| Term | Meaning |
|---|---|
| OTP | One-time password: a short numeric code (example: 6 digits) sent to the user |
| Recovery process / challenge | One password-reset attempt, identified by account + purpose `password_reset` |
| Reset token | Short-lived, single-use credential (or server-side reset session) issued after successful OTP verification, valid only for changing the password |
| Consume | Irreversibly mark a code or token as used so it can never be accepted again |
| Atomic | The check-and-consume step happens as one indivisible operation (transaction, compare-and-set, or atomic cache operation) |
| Verifier | The stored value used to check an OTP (a hash or keyed hash), never the OTP itself |

## 3. High-level flow

1. **Request recovery:** user submits email; server returns a generic response.
2. **Generate + send:** for a known account, server creates a new OTP, invalidates any previous one, stores a verifier, and sends the code to the registered email.
3. **Verify OTP:** user submits the code; server checks it and consumes it atomically.
4. **Issue reset token:** short-lived, single-use, scoped only to password change.
5. **Set new password:** client presents the reset token with the new password; server validates and atomically consumes the token while updating the password.
6. **Finish:** outstanding challenges and tokens are invalidated; old sessions/refresh tokens are revoked; the user is notified; the user signs in normally.

The **server MUST enforce this order** (`FLOW-01`). The UI is only 2–3 screens (email → OTP → new password); the security lives behind them.

## 4. Requirements

### 4.1 Requesting an OTP

| ID | Requirement |
|---|---|
| OTP-01 | The system MUST keep **only one active OTP per account per purpose**. Generating a new OTP MUST invalidate the previous one immediately. This replacement MUST be safe under concurrency, so simultaneous resends cannot leave two active codes. |
| OTP-02 | The response MUST be **the same for existing and non-existent accounts** (prevents user enumeration). Example: "If an account is associated with that email, recovery instructions will be sent." Message text, status code, and observable behavior MUST NOT reveal account existence. |
| OTP-03 | Response **time SHOULD be uniform** for existing and non-existent accounts (e.g. same code path or asynchronous sending, no early exit for unknown emails). |
| OTP-04 | The system MUST enforce a **resend cooldown** (example: no new OTP within 60 seconds of the previous one). |
| OTP-05 | Rate limiting MUST NOT rely on the email alone. Apply **layered limits**: per account/email, per IP address, and where available per device or session. Limits MUST work across all application instances (shared state, not per-process memory). |
| OTP-06 | Rate limiting prevents: email spam to victims, use of the system as a spam tool with someone else's email, and SMS cost abuse if SMS is used. |
| OTP-07 | The system MUST NOT **lock an account** because recovery was requested, and MUST NOT change account state until a valid token is presented. Locking would let an attacker deny service to the real user. |
| OTP-08 | The code MUST be sent **only to the address already registered** to the account, never to an address supplied in the request. |

### 4.2 Generating the OTP

| ID | Requirement |
|---|---|
| OTP-09 | The OTP MUST be generated with a **cryptographically secure random generator**. General-purpose or predictable random functions MUST NOT be used. |
| OTP-10 | Example format: six decimal digits, `000000`–`999999`, about 1,000,000 possibilities. **Leading zeros MUST be supported** (treat the code as a string, not an integer). |
| OTP-11 | The OTP MUST have a **short validity period** (example: 5 minutes). After expiry it MUST be rejected even if the code is correct. |

### 4.3 Storing the OTP

| ID | Requirement |
|---|---|
| OTP-12 | The OTP MUST NOT be stored in plaintext. Store a **verifier**: on verification, compute the verifier of the submitted code and compare it with the stored value. A leaked cache or database then holds no directly usable code. |
| OTP-13 | A plain hash does **not** stop offline guessing of a 6-digit code (the space is tiny). Where practical, use a **keyed verifier (e.g. HMAC)** with a secret stored separately from the data store, and protect that key. Verifier protection **supplements** and never replaces expiry, attempt limits, single use, and rate limiting. |
| OTP-14 | Store challenge state keyed by **account + purpose** with a TTL equal to the validity period. A database with TTL works; Redis or another expiring cache is a common fit because OTPs live only minutes and expire automatically with no cleanup job. Redis is **optional, not required**. |
| OTP-15 | Store only the **minimum state**: account binding, purpose, expiry, failed-attempt count, active/consumed status, and the verifier. |
| OTP-16 | OTPs, reset tokens, and other recovery secrets MUST NOT appear in **application logs** or client-facing error messages. A well-secured system can still leak codes if they sit in plain text in logs many people can read. |

### 4.4 Verifying the OTP

| ID | Requirement |
|---|---|
| VER-01 | Verification attempts MUST be **limited** (example: 5). Each wrong code increments a failed-attempt counter. |
| VER-02 | When the limit is reached, the OTP MUST be **cancelled**, even if the user later submits the correct code. A new OTP MUST then be requested. |
| VER-03 | A code is accepted only if **all** hold: well-formed, correct, unexpired, unused, within its attempt limit, and bound to **this account** and **this purpose**. Malformed, expired, wrong, consumed, superseded, and purpose-mismatched codes MUST be rejected. |
| VER-04 | The OTP MUST be **bound to its purpose**. A password-reset OTP MUST NOT confirm an email change, authorize login, or serve any other operation, and codes from other flows (login OTP, MFA, email-change) MUST NOT be accepted here. Keep these challenges separate. |
| VER-05 | The OTP MUST be **single-use**. After the first successful verification it is consumed and can never be accepted again (replay protection). It MUST NOT stay valid for the rest of its lifetime. |
| VER-06 | **Verify-and-consume MUST be atomic.** Do not "read → check valid → later mark used" in separate steps. Exactly one request may move the code from valid to used; any concurrent or later request MUST find it consumed and be rejected. |

**Why VER-06 matters (race condition):** if the user double-clicks Verify, or a network retry sends two requests at once, both can read the code as valid and unused, and both succeed unless check-and-consume is atomic. This separates code that passes tests from a system that holds under real load.

### 4.5 After successful verification

| ID | Requirement |
|---|---|
| TOK-01 | OTP success MUST NOT let the client submit arbitrary reset requests without proof. The server MUST issue a **short-lived reset token** (or server-side reset session) dedicated only to changing the password. |
| TOK-02 | The reset token MUST be **single-use**, generated with a cryptographically secure random generator, and bound to the account and the password-reset purpose. |
| TOK-03 | The token MUST NOT authorize login, email change, or any operation other than the password change. |
| TOK-04 | The password-change step MUST **validate and atomically consume** the token while updating the password. Two simultaneous password updates MUST NOT both consume the same token. Expired, replayed, or purpose-mismatched tokens MUST be rejected. |
| TOK-05 | This separates two stages: (a) proving email ownership, (b) changing the password. |
| TOK-06 | The new password MUST follow the application's normal password policy and secure password-storage practices. |

### 4.6 After the password changes

| ID | Requirement |
|---|---|
| POST-01 | The system SHOULD **revoke the user's old sessions and refresh tokens** (per a documented policy). Reason: an attacker already inside the account with a valid refresh token does not need the password and could keep minting access tokens. |
| POST-02 | The user SHOULD be **notified** that the password changed (example: "The password for your account was changed. If this was not you, contact us immediately."). Mandatory for sensitive accounts. The notice MUST NOT contain the password. |
| POST-03 | All outstanding recovery challenges and reset tokens for the account MUST be **invalidated**. |
| POST-04 | The system MUST NOT email the password and MUST NOT automatically log the user in after reset. The user signs in through the normal mechanism. |

### 4.7 Server-side flow enforcement

| ID | Requirement |
|---|---|
| FLOW-01 | The **server MUST enforce the sequence**: request recovery → verify OTP → issue restricted reset authorization → set password → invalidate recovery authorization. |
| FLOW-02 | **Every endpoint that can change a password** MUST reject requests without valid, unexpired, purpose-bound reset authorization. The system MUST NOT rely on the front end to enforce the order. If the password-change endpoint skips this check, every other protection is worthless. |
| FLOW-03 | Challenge creation, resend replacement, OTP verification/consumption, and reset-token consumption MUST be safe under concurrent requests, using atomic datastore operations or transactions rather than separate read-then-write steps. |

## 5. Threat → control map

| Threat | Controls |
|---|---|
| Old code stolen/leaked but still works | OTP-01 |
| Spamming Send OTP (email spam, SMS cost, spam tool) | OTP-04, OTP-05, OTP-06 |
| User enumeration (message, status code, or timing) | OTP-02, OTP-03 |
| Denial of service by locking the victim's account | OTP-07 |
| Code sent to attacker-chosen address | OTP-08 |
| Brute-forcing the ~1M code space | VER-01, VER-02, OTP-11, OTP-13 |
| Predictable codes or tokens | OTP-09, TOK-02 |
| Leaked cache/database exposes usable codes; offline guessing | OTP-12, OTP-13 |
| Codes visible in logs or error messages | OTP-16 |
| Replay of a used code | VER-05 |
| Double-submit / retry race condition | VER-06, TOK-04, FLOW-03 |
| Code or token reused for a different purpose | VER-03, VER-04, TOK-03 |
| Arbitrary reset requests after verification | TOK-01 to TOK-05, FLOW-01, FLOW-02 |
| Attacker keeps access via existing refresh token | POST-01, POST-02, POST-03 |
| Client skips steps | FLOW-01, FLOW-02 |
| Inconsistent limits across servers | OTP-05, FLOW-03 |

## 6. Guidance for AI coding tools

When implementing this in an existing project:

1. **Plan first.** Present the implementation plan (files, endpoints, data model, chosen values) and wait for explicit approval before writing or changing code.
2. **Inspect before changing anything:** the framework, authentication and session model, email provider, persistence layer, and existing tests. Follow established project conventions.
3. **Do not assume Redis** or add dependencies without a concrete need. Use what the project already has (database with TTL, existing cache).
4. **Implement the entire server-side flow**, not just the screens. Identify every endpoint that can change a password and make each one check reset authorization (`FLOW-02`).
5. **Store only the minimum challenge state** (`OTP-15`).
6. **Make rate limits and atomic operations work across application instances** (`OTP-05`, `FLOW-03`). Per-process memory is not sufficient when more than one instance runs.
7. **Preserve existing password rules and password hashing.** Do not email passwords; do not auto-authenticate after reset.
8. **Manage the HMAC key** (`OTP-13`) as a secret: outside the data store, outside source control, and never logged.
9. **Document the chosen values**: code length, expiry, resend cooldown, attempt limit, throttling policy, session-revocation policy.
10. **Add security-focused tests** (Section 7) and report which tests were run and their results. Do **not** claim the implementation is secure based only on a happy-path test.

## 7. Acceptance tests

An implementation is correct only if all of these pass.

**Request and enumeration**
1. Existing and non-existent emails receive the same public response (message and status code), with no observable timing difference.
2. A second request inside the cooldown window (example: 60 s) is rejected or throttled.
3. Many requests for different emails from one IP are throttled; many requests for one email from different IPs are throttled; limits hold across multiple application instances.
4. Repeated recovery requests never lock the account.

**Code lifecycle**
5. Request OTP A, then OTP B for the same account: A fails, B succeeds. Concurrent resends cannot leave multiple active codes.
6. An expired correct code is rejected.
7. After the maximum wrong attempts, the OTP is cancelled; the correct code afterwards is rejected and a new OTP is required.
8. Wrong, malformed, consumed, and superseded codes are rejected.
9. Codes with leading zeros (e.g. `004217`) are accepted and checked correctly.
10. After one successful verification, the same code is rejected.
11. Two simultaneous verification requests with the correct code: exactly one succeeds.
12. A password-reset code is rejected for any other purpose (email change, login, MFA), and codes from those flows are rejected here.

**Storage and secrecy**
13. Inspecting the cache/database shows only a verifier, never the plain code.
14. OTPs and reset tokens appear in no logs and no client-facing errors.

**Reset token and flow**
15. The password-change endpoint rejects requests without a valid reset token; the token expires, works once, and cannot be used for login or other operations.
16. Two simultaneous password updates cannot both consume the same reset token.
17. Calling the password-change endpoint directly, skipping OTP verification, fails.

**After reset**
18. A successful reset follows the password policy, invalidates all outstanding recovery challenges and tokens, notifies the user, and applies the documented session-revocation policy (previously issued refresh tokens no longer work).
19. No password is emailed and the user is not automatically logged in.

## 8. Summary checklist

- [ ] One active OTP per account per purpose; concurrent-safe replacement
- [ ] Generic response: same message, status code, and timing (no user enumeration)
- [ ] Resend cooldown + layered rate limits that work across instances
- [ ] No account lockout from recovery requests
- [ ] Code sent only to the registered address
- [ ] Cryptographically secure random generation; leading zeros supported
- [ ] Short expiry (example: 5 minutes)
- [ ] OTP stored only as a verifier (keyed where practical), account + purpose + TTL; never logged
- [ ] Limited verification attempts; OTP cancelled at the limit
- [ ] Single-use OTP with **atomic** verify-and-consume
- [ ] OTP and token bound to account + purpose; unusable elsewhere
- [ ] Short-lived, single-use reset token, atomically consumed at password change
- [ ] Old sessions/refresh tokens revoked; outstanding challenges invalidated
- [ ] Notification sent; no emailed password; no auto-login
- [ ] Server enforces the full flow on every password-changing endpoint
- [ ] Tests run and reported, including concurrency and cross-instance cases

## 9. References

- OWASP Forgot Password Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html
- NIST SP 800-63B-4: https://pages.nist.gov/800-63-4/sp800-63b.html

Note: the keyed-verifier recommendation (`OTP-13`) is engineering guidance rather than a quotation from either reference. An unkeyed hash of a 6-digit code can be brute-forced offline in negligible time if the data store leaks.

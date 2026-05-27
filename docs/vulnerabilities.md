# Vulnerability Matrix & Remediation Guide

This document catalogs the 16 vulnerabilities implemented in **DVGA-Node**, including their testing strategies and code-level fixes.

## 1. BOLA (Broken Object Level Authorization)
* **Risk:** Exposes other users' records (e.g. `profile(id: "3")`) based on unchecked inputs.
* **Fix:** Verify user identity context owner properties:
  ```javascript
  if (profile.user_id !== context.user.id) throw new Error("Denied");
  ```

## 2. IDOR (Insecure Direct Object Reference)
* **Risk:** Allows users to modify details of records they don't own via mutated ID values.
* **Fix:** Query target tables to verify ownership before saving updates.

## 3. Weak JWT Validation
* **Risk:** Accepting tokens with header `alg: none` or signature validation bypasses.
* **Fix:** Enforce algorithms whitelist (`['HS256']`) and reject invalid signatures.

## 4. Broken Access Control
* **Risk:** Exposing administrative tables/mutations to unauthenticated or regular roles.
* **Fix:** Restrict resolver returns based on `context.user.role === 'admin'`.

## 5. SQL Injection
* **Risk:** Constructing SQL queries using string template formatting or concatenation.
* **Fix:** Always parameterize inputs:
  ```javascript
  db.query('SELECT * FROM users WHERE email = $1', [email]);
  ```

## 6. Stored XSS
* **Risk:** Saving unescaped input scripting tags which execute in client browsers.
* **Fix:** HTML entity encode inputs before outputting or database saving.

## 7. Reflected XSS
* **Risk:** Immediate reflection of search inputs without output encoding.
* **Fix:** Sanitize user outputs through escaping functions.

## 8. SSRF (Server-Side Request Forgery)
* **Risk:** Forcing the server to request loopbacks or local network endpoints.
* **Fix:** Whitelist domain scopes and block private IP address spaces.

## 9. Brute Force Throttling Failure
* **Risk:** Allowing rapid dictionary login attempts.
* **Fix:** Introduce rate limiters and authentication delays on credentials failure.

## 10. Command Execution Risks
* **Risk:** Shell execution of user strings via processes like `child_process.exec`.
* **Fix:** Avoid shell creation. Use arguments arrays or whitelists.

## 11. GraphQL Introspection Exposure
* **Risk:** Schema exposure revealing private operations and types.
* **Fix:** Disable introspection in production configs.

## 12. Excessive Data Exposure
* **Risk:** Serializing unneeded fields (e.g., password hashes) in API payloads.
* **Fix:** Strip fields from schema definitions and SQL queries.

## 13. Field-Level Authorization Failure
* **Risk:** Accessing admin properties inside parent objects.
* **Fix:** Apply auth boundaries inside nested child resolvers.

## 14. Sensitive Error Leakage
* **Risk:** Leaking database system details and traces.
* **Fix:** Genericize error responses in customized formatters.

## 15. Insecure File Upload Validation
* **Risk:** Storing malicious executable script uploads in host folders.
* **Fix:** Whitelist extensions and MIME tags, and rename files.

## 16. Weak Password Policy
* **Risk:** Standard dictionary logins succeed.
* **Fix:** Restrict accounts creation to strong password structures.

---

## 17. Broken Authentication
* **OWASP Reference:** [API2:2023](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/)
* **Risk:** The `loginWithToken` mutation accepts ANY session token value without server-side verification. An attacker who knows a user's email can authenticate as that user by providing any arbitrary string as the `sessionToken`. This completely bypasses password-based authentication.
* **Exploit:**
  ```graphql
  mutation {
    loginWithToken(email: "admin@lab.local", sessionToken: "any-string-works") {
      token
      user { id email role is_admin }
    }
  }
  ```
* **Impact:** Full account takeover of any user (including admin) without knowing their password.
* **Fix:** Disable unverified token-based login. If session refresh is needed, validate tokens against a server-side session store (Redis/database), check expiration, and bind to device fingerprints:
  ```javascript
  // Reject all token-based logins — force password authentication
  throw new Error('Token-based authentication is disabled.');
  ```

## 18. Broken Object Property Level Authorization
* **OWASP Reference:** [API3:2023](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/)
* **Risk:** The `updateUserProfile` mutation blindly applies ALL submitted fields — including privileged properties `role` and `is_admin` — without checking whether the authenticated user is authorized to modify those properties. A regular user can escalate their own privileges to admin via mass assignment.
* **Exploit (as Alice, user ID 2):**
  ```graphql
  mutation {
    updateUserProfile(userId: "2", role: "admin", is_admin: true) {
      id email role is_admin message
    }
  }
  ```
* **Impact:** Privilege escalation — any user can make themselves an admin.
* **Fix:** Implement property-level authorization. Regular users can only modify non-privileged fields (e.g., `email`). Privileged fields (`role`, `is_admin`) require admin role:
  ```javascript
  if ((role !== undefined || is_admin !== undefined) && context.user.role !== 'admin') {
    throw new Error('Only administrators can modify role or admin status.');
  }
  ```

## 19. Broken Function Level Authorization
* **OWASP Reference:** [API5:2023](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/)
* **Risk:** Administrative functions (`transferFunds`, `deleteUser`, `transactions` query) are exposed to any authenticated user without role verification. A regular user can transfer funds between ANY accounts, view all financial records, or delete other user accounts.
* **Exploit (as Alice — transfer funds from Admin):**
  ```graphql
  mutation {
    transferFunds(fromUserId: "1", toUserId: "2", amount: 10000, description: "Stolen") {
      id amount description status
    }
  }
  ```
* **Exploit (as Alice — view admin financial records):**
  ```graphql
  query {
    transactions { id from_user_id to_user_id amount description status }
  }
  ```
* **Impact:** Financial fraud, unauthorized data access, account deletion.
* **Fix:** Enforce role-based access control (RBAC) on every privileged resolver:
  ```javascript
  if (!context.user || context.user.role !== 'admin') {
    throw new Error('Access Denied: Only administrators can perform fund transfers.');
  }
  ```

## 20. Unrestricted Access to Sensitive Business Flows
* **OWASP Reference:** [API6:2023](https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/)
* **Risk:** The coupon system has no authentication, no rate limiting, and no enforcement of usage limits. Attackers can: (1) enumerate all coupon codes including internal staff discounts without logging in, (2) apply high-value staff coupons (75% off) as anonymous users, and (3) redeem the same coupon unlimited times, ignoring the `max_uses` limit.
* **Exploit (enumerate coupons without auth):**
  ```graphql
  query {
    coupons { id code discount_percent max_uses current_uses is_active }
  }
  ```
* **Exploit (abuse staff coupon repeatedly):**
  ```graphql
  mutation {
    applyCoupon(code: "STAFF75") {
      id code discount_percent current_uses max_uses
    }
  }
  ```
  Run 5+ times — `current_uses` exceeds `max_uses` with no enforcement.
* **Impact:** Financial loss from unlimited discount abuse, internal coupon code leakage.
* **Fix:** Require authentication, enforce `max_uses` limits, restrict internal coupons to staff roles, and implement rate limiting:
  ```javascript
  if (!context.user) throw new Error('Authentication required.');
  if (coupon.current_uses >= coupon.max_uses) {
    throw new Error('Coupon has reached its maximum number of uses.');
  }
  if (coupon.code.startsWith('STAFF') && context.user.role !== 'admin') {
    throw new Error('This coupon is restricted to staff members.');
  }
  ```


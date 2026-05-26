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

# Architecture Overview

This document describes the architectural layout and flow of the **DVGA-Node** educational lab.

```
       +--------------------------------------------+
       |           Client UI (public SPA)           |
       +--------------------------------------------+
                             |
                   HTTP POST | /graphql
                             v
       +--------------------------------------------+
       |           Express Web Server               |
       +--------------------------------------------+
                             |
                             +---> [auth.js JWT Middleware]
                             |
                             v
       +--------------------------------------------+
       |             Apollo Server v4               |
       +--------------------------------------------+
                             |
            +----------------+----------------+
            |                                 |
            v                                 v
     [VULNERABLE Path]                [MITIGATED Path]
     - Raw string interpolation       - Parameterized queries
     - No ownership checks            - Strict identity comparison
     - Error stack leak               - Sanitized error wrappers
            |                                 |
            +----------------+----------------+
                             |
                             v
       +--------------------------------------------+
       |        PostgreSQL Database (pg pool)       |
       +--------------------------------------------+
```

## Core Design Decisions

### 1. No ORMs (Direct Database Access)
To show SQL injection vulnerabilities clearly, we avoid ORMs like Sequelize or Prisma. Instead, we use the `pg` driver directly.
* Resolvers use `db.unsafeQuery(queryStr)` in vulnerable mode to execute concatenated queries.
* Resolvers use `db.query(text, params)` in mitigated mode to run parameterized inputs.

### 2. Runtime Context
Authentication middleware parses incoming Authorization Bearer headers. It handles vulnerabilities like `alg: none` and signature bypasses, attaching user sessions (`req.user`) directly to the request object. Apollo Server injects this session context into resolver function calls.

### 3. Resolution Splitting
Inside `server/graphql/resolvers.js`, queries consult `config.getSecurityMode()` to dynamically branch between vulnerable and secure resolver paths. This allows immediate testing of query payloads on identical schema fields.

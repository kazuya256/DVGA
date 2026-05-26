# Security Notice

> [!WARNING]
> **DELIBERATELY VULNERABLE LAB - STRICTLY EDUCATIONAL USE ONLY**
> This application contains intentionally vulnerable code modules representing critical web API flaws.

## Safe Usage Guidelines

1. **Host Boundary Restrictions:**
   This lab must **ONLY** be hosted in offline, local, or firewalled container environments. Never expose the GraphQL API (`/graphql`) or UI portal (`/`) to public networks.

2. **Network Isolation:**
   When running outside Docker, ensure your local firewall blocks port 5013 to external interfaces. In Docker environments, networking is isolated to the `dvga-network` bridge, exposing only port 5013 to localhost.

3. **Database Security:**
   The training database contains static mock values. Do not store real production keys, passwords, or personal identity information in the database.

4. **Malicious Payloads Warning:**
   Exploiting modules like SSRF or Command Injection on host environments could be hazardous if altered. The default implementation contains sandboxing checks on Windows hosts to mitigate threats. Do not bypass these sandboxes outside isolated VM containers.

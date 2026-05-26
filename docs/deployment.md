# Deployment Guidelines

> [!WARNING]
> Hosting this application on public-facing internet servers is highly discouraged. If you must deploy to staging or virtual private servers (VPS) for testing, apply network-level authentication (Basic Auth or VPN whitelist) to prevent external access.

## Reverse Proxy Configuration (Nginx)

When deploying to a VPS (e.g. DigitalOcean, Linode), use Nginx as a reverse proxy. Restrict access to designated IP ranges:

```nginx
server {
    listen 80;
    server_name dvga-lab.local;

    location / {
        # Restrict to training VPN IP range
        allow 10.0.0.0/8;
        deny all;

        proxy_pass http://localhost:5013;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

## Cloud Host Deployments

### Railway / Render
1. Create a **PostgreSQL** database service on Railway/Render.
2. Create a Web Service connected to your GitHub repository.
3. Configure Environment variables:
   * `DB_HOST`: The external host URL of the Postgres service.
   * `DB_PORT`: Postgres connection port.
   * `DB_USER`: Database login user.
   * `DB_PASSWORD`: Database login password.
   * `DB_NAME`: Database target name.
   * `SECURITY_MODE`: `VULNERABLE` (or `MITIGATED`).
   * `JWT_SECRET`: A custom string for training token signature checking.
4. Deployment command:
   * Build command: `npm install`
   * Start command: `npm start`

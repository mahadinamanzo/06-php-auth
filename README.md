# SWD Auth

A small PHP and MySQL account-registration and sign-in application.

## Requirements and setup

- PHP 8.2 or newer with PDO MySQL
- MySQL or MariaDB
- Apache or another PHP-capable web server

1. Configure `DB_HOST`, `DB_NAME`, `DB_USER`, and `DB_PASS` in the environment, or use the development defaults in `config.php`.
2. Import `schema.sql` into MySQL. The schema creates the database and applies additive updates for the user and login-attempt fields.
3. For local XAMPP development, open `http://localhost/swd/06-php-auth/register.php`.
4. Create an account and sign in. Promote the first administrator from a terminal:

   ```powershell
   C:\xampp\php\php.exe C:\xampp\htdocs\swd\06-php-auth\promote-admin.php me@example.com
   ```

5. Administrators can manage roles at `/admin/users.php`.

## Security features

- Passwords use PHP's `password_hash()` / `password_verify()` APIs, with rehashing when the configured algorithm changes.
- Login errors do not reveal whether an email address exists. Failed attempts are recorded by email and IP; five failures in 15 minutes temporarily block further attempts.
- Sessions use strict mode, cookie-only IDs, HttpOnly, SameSite=Lax, and Secure cookies outside development. Successful sign-in and password changes regenerate the session ID.
- Sessions expire after 30 minutes of inactivity. Logout is POST-only, CSRF-protected, clears session data, and removes the session cookie.
- Mutating forms use session-bound CSRF tokens. SQL statements with user input use PDO prepared statements.
- User-controlled content is HTML-escaped. Intended login destinations are checked as same-site relative paths.
- Admin routes check the user's current database role and return a friendly 403 response to non-admins. Role changes are CSRF-protected and an administrator cannot demote their own account.
- Responses set `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, and `Cache-Control: no-store`. HTTPS responses also receive HSTS.

## Production HTTPS configuration

Do not deploy authentication over plaintext HTTP. Terminate TLS at Apache or a trusted reverse proxy and ensure PHP's `$_SERVER['HTTPS']` is set to `on` for HTTPS requests. Do not copy an untrusted `X-Forwarded-Proto` header into this variable.

Set:

```text
APP_ENV=production
APP_HTTPS_HOST=auth.example.com
```

`APP_HTTPS_HOST` is the canonical HTTPS hostname, optionally with a port. Non-development requests over HTTP are redirected to that host for GET/HEAD requests; other HTTP methods are rejected without running application routes. If the canonical host is not configured, HTTP requests fail with a service-unavailable response. Secure session cookies are always enabled outside development. HSTS is sent only over HTTPS.

Use a unique, least-privilege database account in production. Do not expose PHP errors to users or commit credentials to source control.

## Security review findings

| # | Severity | Finding | Resolution |
|---|---|---|---|
| 1 | HIGH | Production deployments could accept authentication over HTTP, exposing credentials and non-Secure session cookies to interception. | Non-development HTTP requests are redirected/rejected using the configured canonical HTTPS host; non-development cookies are Secure and HTTPS responses include HSTS. |

The application still depends on the deployment providing valid TLS and correctly marking HTTPS at the trusted web-server/proxy boundary.

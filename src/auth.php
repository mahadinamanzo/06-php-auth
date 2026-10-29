<?php
declare(strict_types=1);

const IDLE_TIMEOUT_SECONDS = 1800;

function current_user(): ?array
{
    static $loaded = false;
    static $user = null;

    if ($loaded) {
        return $user;
    }

    $loaded = true;
    $userId = $_SESSION['user_id'] ?? null;

    if (!is_int($userId) || $userId < 1) {
        return null;
    }

    $statement = db()->prepare(
        'SELECT id, name, email, role, created_at, last_login_at
         FROM users
         WHERE id = :id
         LIMIT 1'
    );
    $statement->execute(['id' => $userId]);
    $record = $statement->fetch();

    if ($record === false) {
        return null;
    }

    $user = $record;
    $_SESSION['role'] = (string) $record['role'];

    return $user;
}

function require_login(): void
{
    if (current_user() !== null) {
        return;
    }

    $requestedUrl = $_SERVER['REQUEST_URI'] ?? '';

    if (is_string($requestedUrl) && is_safe_relative_url($requestedUrl)) {
        $_SESSION['_intended_url'] = $requestedUrl;
    }

    redirect('login.php');
}

function require_guest(): void
{
    if (current_user() !== null) {
        redirect('dashboard.php');
    }
}

function require_role(string $role): void
{
    require_login();

    $user = current_user();

    if ($user === null || $user['role'] !== $role) {
        render_forbidden_page();
    }
}

function render_forbidden_page(): void
{
    http_response_code(403);
    $stylesheet = basename(dirname($_SERVER['SCRIPT_NAME'] ?? '')) === 'admin'
        ? '../assets/auth.css'
        : 'assets/auth.css';
    ?>
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Access denied</title>
        <link rel="stylesheet" href="<?= e($stylesheet) ?>">
    </head>
    <body>
    <?php render_navbar(); ?>
    <main class="auth-page">
        <section class="auth-card" aria-labelledby="forbidden-title">
            <p class="eyebrow">403 - Access denied</p>
            <h1 id="forbidden-title">You don't have permission to view this page.</h1>
            <p>Your account doesn't have the required access. If you think this is a mistake, contact an administrator.</p>
            <p><a href="dashboard.php">Return to dashboard</a></p>
        </section>
    </main>
    </body>
    </html>
    <?php
    exit;
}

function login_throttle_status(string $email, ?string $ipAddress): ?int
{
    $pdo = db();
    $blockedForSeconds = [];

    $emailAttempts = $pdo->prepare(
        'SELECT TIMESTAMPDIFF(SECOND, attempted_at, CURRENT_TIMESTAMP) AS age_seconds
         FROM login_attempts
         WHERE email = :email
           AND attempted_at >= CURRENT_TIMESTAMP - INTERVAL 15 MINUTE
         ORDER BY attempted_at DESC
         LIMIT 5'
    );
    $emailAttempts->execute(['email' => $email]);
    $emailResults = $emailAttempts->fetchAll();
    if (count($emailResults) >= 5) {
        $blockedForSeconds[] = max(1, 900 - (int) $emailResults[4]['age_seconds']);
    }

    if ($ipAddress !== null) {
        $ipAttempts = $pdo->prepare(
            'SELECT TIMESTAMPDIFF(SECOND, attempted_at, CURRENT_TIMESTAMP) AS age_seconds
             FROM login_attempts
             WHERE ip = :ip_address
               AND attempted_at >= CURRENT_TIMESTAMP - INTERVAL 15 MINUTE
             ORDER BY attempted_at DESC
             LIMIT 5'
        );
        $ipAttempts->bindValue(':ip_address', $ipAddress);
        $ipAttempts->execute();
        $ipResults = $ipAttempts->fetchAll();

        if (count($ipResults) >= 5) {
            $blockedForSeconds[] = max(1, 900 - (int) $ipResults[4]['age_seconds']);
        }
    }

    return $blockedForSeconds === [] ? null : max($blockedForSeconds);
}

function record_failed_login(string $email, ?string $ipAddress): void
{
    $statement = db()->prepare(
        'INSERT INTO login_attempts (email, ip) VALUES (:email, :ip_address)'
    );
    $statement->bindValue(':email', $email);
    $statement->bindValue(':ip_address', $ipAddress, $ipAddress === null ? PDO::PARAM_NULL : PDO::PARAM_STR);
    $statement->execute();
}

function clear_login_attempts(string $email, ?string $ipAddress): void
{
    if ($ipAddress === null) {
        $statement = db()->prepare('DELETE FROM login_attempts WHERE email = :email');
        $statement->execute(['email' => $email]);
        return;
    }

    $statement = db()->prepare(
        'DELETE FROM login_attempts WHERE email = :email OR ip = :ip_address'
    );
    $statement->bindValue(':email', $email);
    $statement->bindValue(':ip_address', $ipAddress);
    $statement->execute();
}

function normalize_login_email(string $email): string
{
    $normalized = function_exists('mb_strtolower')
        ? mb_strtolower(trim($email), 'UTF-8')
        : strtolower(trim($email));

    return function_exists('mb_strcut')
        ? mb_strcut($normalized, 0, 254, 'UTF-8')
        : substr($normalized, 0, 254);
}

function enforce_idle_timeout(): void
{
    if (!isset($_SESSION['user_id'])) {
        return;
    }

    $lastActivity = $_SESSION['last_activity_at'] ?? null;

    if (
        !is_int($lastActivity)
        || $lastActivity > time()
        || time() - $lastActivity >= IDLE_TIMEOUT_SECONDS
    ) {
        end_session();
        flash('error', 'You were signed out after 30 minutes of inactivity.');
        return;
    }

    $_SESSION['last_activity_at'] = time();
}

function end_session(): void
{
    $_SESSION = [];

    if (ini_get('session.use_cookies')) {
        $cookie = session_get_cookie_params();
        $options = [
            'expires' => time() - 42000,
            'path' => $cookie['path'],
            'domain' => $cookie['domain'],
            'secure' => $cookie['secure'],
            'httponly' => $cookie['httponly'],
        ];

        if (isset($cookie['samesite'])) {
            $options['samesite'] = $cookie['samesite'];
        }

        setcookie(session_name(), '', $options);
    }

    session_destroy();
    unset($_COOKIE[session_name()]);
    session_id('');
    session_start();
}

function is_safe_relative_url(string $url): bool
{
    if (
        $url === ''
        || $url[0] !== '/'
        || str_starts_with($url, '//')
        || str_contains($url, '\\')
        || preg_match('/[\x00-\x1F\x7F]/', $url) === 1
    ) {
        return false;
    }

    $parts = parse_url($url);

    return $parts !== false
        && !isset($parts['scheme'])
        && !isset($parts['host'])
        && !isset($parts['user'])
        && !isset($parts['pass']);
}

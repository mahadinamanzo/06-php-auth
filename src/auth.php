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

    if (
        $user === null
        || ($_SESSION['role'] ?? null) !== $role
        || $user['role'] !== $role
    ) {
        http_response_code(403);
        exit('You do not have permission to access this page.');
    }
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

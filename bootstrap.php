<?php
declare(strict_types=1);

require_once __DIR__ . '/config.php';

error_reporting(E_ALL);
ini_set('display_errors', APP_ENV === 'development' ? '1' : '0');
ini_set('display_startup_errors', APP_ENV === 'development' ? '1' : '0');

require_once __DIR__ . '/src/db.php';
require_once __DIR__ . '/src/helpers.php';
require_once __DIR__ . '/src/csrf.php';
require_once __DIR__ . '/src/auth.php';
require_once __DIR__ . '/src/navigation.php';

$isHttps = isset($_SERVER['HTTPS'])
    && $_SERVER['HTTPS'] !== ''
    && strtolower($_SERVER['HTTPS']) !== 'off';

header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Cache-Control: no-store');

if ($isHttps) {
    header('Strict-Transport-Security: max-age=31536000');
}

if (APP_ENV !== 'development' && !$isHttps) {
    if (APP_HTTPS_HOST === '') {
        http_response_code(503);
        exit('HTTPS is required. Configure APP_HTTPS_HOST and enable HTTPS for this application.');
    }

    if (
        preg_match('/\A([A-Za-z0-9.-]+)(?::([0-9]{1,5}))?\z/D', APP_HTTPS_HOST, $hostParts) !== 1
        || (
            filter_var($hostParts[1], FILTER_VALIDATE_IP) === false
            && filter_var($hostParts[1], FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false
        )
        || (isset($hostParts[2]) && ((int) $hostParts[2] < 1 || (int) $hostParts[2] > 65535))
    ) {
        throw new RuntimeException('APP_HTTPS_HOST must be a valid hostname or IP address, optionally with a port.');
    }

    $requestUri = $_SERVER['REQUEST_URI'] ?? '/';

    if (!is_string($requestUri) || !is_safe_relative_url($requestUri)) {
        $requestUri = '/';
    }

    if (in_array($_SERVER['REQUEST_METHOD'] ?? 'GET', ['GET', 'HEAD'], true)) {
        header('Location: https://' . APP_HTTPS_HOST . $requestUri, true, 308);
        exit;
    }

    http_response_code(400);
    exit('HTTPS is required. Resubmit this request over HTTPS.');
}

if (session_status() !== PHP_SESSION_ACTIVE) {
    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');

    session_name('SWDSESSID');
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'secure' => $isHttps || APP_ENV !== 'development',
        'httponly' => true,
        'samesite' => 'Lax',
    ]);

    session_start();
}

enforce_idle_timeout();

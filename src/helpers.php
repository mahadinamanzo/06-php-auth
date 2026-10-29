<?php
declare(strict_types=1);

function e(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function redirect(string $url): void
{
    header('Location: ' . $url, true, 303);
    exit;
}

function flash(string $key, mixed $value = null): mixed
{
    if (func_num_args() > 1) {
        $_SESSION['_flash'][$key] = $value;
        return null;
    }

    $stored = $_SESSION['_flash'][$key] ?? null;
    unset($_SESSION['_flash'][$key]);

    return $stored;
}

function old(string $key, string $default = ''): string
{
    $value = $_SESSION['_old'][$key] ?? $default;

    return is_string($value) ? $value : $default;
}

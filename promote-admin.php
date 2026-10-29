<?php
declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/src/db.php';

if ($argc !== 2 || filter_var($argv[1], FILTER_VALIDATE_EMAIL) === false) {
    fwrite(STDERR, "Usage: php promote-admin.php email@example.com\n");
    exit(1);
}

$statement = db()->prepare('SELECT id, role FROM users WHERE email = :email LIMIT 1');
$statement->execute(['email' => $argv[1]]);
$user = $statement->fetch();

if ($user === false) {
    fwrite(STDERR, "No user found with that email address.\n");
    exit(1);
}

if ($user['role'] === 'admin') {
    fwrite(STDOUT, "That user is already an administrator.\n");
    exit(0);
}

$update = db()->prepare('UPDATE users SET role = :role WHERE id = :id');
$update->execute([
    'role' => 'admin',
    'id' => $user['id'],
]);

fwrite(STDOUT, "Administrator role granted to {$argv[1]}.\n");

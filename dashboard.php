<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

if (!isset($_SESSION['user_id']) || !is_int($_SESSION['user_id'])) {
    redirect('register.php');
}

$userName = isset($_SESSION['user_name']) && is_string($_SESSION['user_name'])
    ? $_SESSION['user_name']
    : 'there';
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Dashboard</title>
    <link rel="stylesheet" href="assets/auth.css">
</head>
<body>
<main class="auth-page">
    <section class="auth-card" aria-labelledby="dashboard-title">
        <p class="eyebrow">SWD Auth</p>
        <h1 id="dashboard-title">Welcome, <?= e($userName) ?>.</h1>
        <p>Your account is registered and you are signed in.</p>
    </section>
</main>
</body>
</html>

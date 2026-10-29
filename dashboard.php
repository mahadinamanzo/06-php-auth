<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

require_login();

$user = current_user();
$lastLogin = $user['last_login_at'] ?? null;
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
<?php render_navbar(); ?>
<main class="auth-page">
    <section class="auth-card" aria-labelledby="dashboard-title">
        <p class="eyebrow">SWD Auth</p>
        <h1 id="dashboard-title">Welcome, <?= e((string) $user['name']) ?>.</h1>
        <p>Your account is signed in.</p>
        <dl>
            <dt>Email</dt>
            <dd><?= e((string) $user['email']) ?></dd>
            <dt>Role</dt>
            <dd><?= e((string) $user['role']) ?></dd>
            <dt>Member since</dt>
            <dd><?= e((string) $user['created_at']) ?></dd>
            <dt>Last login</dt>
            <dd><?= is_string($lastLogin) ? e($lastLogin) : 'Not available' ?></dd>
        </dl>
        <form method="post" action="logout.php">
            <?= csrf_field() ?>
            <button type="submit">Sign out</button>
        </form>
    </section>
</main>
</body>
</html>

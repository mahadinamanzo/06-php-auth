<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

require_guest();

$error = null;
$email = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!csrf_verify()) {
        http_response_code(403);
        $error = 'Your form session expired. Please reload the page and try again.';
    } else {
        $emailInput = $_POST['email'] ?? '';
        $passwordInput = $_POST['password'] ?? '';
        $email = is_string($emailInput) ? trim($emailInput) : '';
        $password = is_string($passwordInput) ? $passwordInput : '';

        $statement = db()->prepare(
            'SELECT id, password_hash, role
             FROM users
             WHERE email = :email
             LIMIT 1'
        );
        $statement->execute(['email' => $email]);
        $user = $statement->fetch();

        if (
            $user === false
            || !is_string($user['password_hash'])
            || !password_verify($password, $user['password_hash'])
        ) {
            $error = 'Invalid email or password';
        } else {
            if (password_needs_rehash($user['password_hash'], PASSWORD_DEFAULT)) {
                $passwordHash = password_hash($password, PASSWORD_DEFAULT);

                if ($passwordHash === false) {
                    throw new RuntimeException('Unable to secure the password.');
                }

                $updatePassword = db()->prepare(
                    'UPDATE users SET password_hash = :password_hash WHERE id = :id'
                );
                $updatePassword->execute([
                    'password_hash' => $passwordHash,
                    'id' => $user['id'],
                ]);
            }

            $updateLogin = db()->prepare(
                'UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = :id'
            );
            $updateLogin->execute(['id' => $user['id']]);

            if (!session_regenerate_id(true)) {
                throw new RuntimeException('Unable to renew the session.');
            }

            unset($_SESSION['_csrf_token'], $_SESSION['_old']);
            $_SESSION['user_id'] = (int) $user['id'];
            $_SESSION['role'] = (string) $user['role'];
            $_SESSION['last_activity_at'] = time();

            $intendedUrl = $_SESSION['_intended_url'] ?? null;
            unset($_SESSION['_intended_url']);

            redirect(
                is_string($intendedUrl) && is_safe_relative_url($intendedUrl)
                    ? $intendedUrl
                    : 'dashboard.php'
            );
        }
    }
}

$email = old('email', $email);
unset($_SESSION['_old']);
$flashError = flash('error');
$flashSuccess = flash('success');
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Sign in</title>
    <link rel="stylesheet" href="assets/auth.css">
</head>
<body>
<main class="auth-page">
    <section class="auth-card" aria-labelledby="login-title">
        <header class="auth-header">
            <p class="eyebrow">SWD Auth</p>
            <h1 id="login-title">Sign in</h1>
            <p>Sign in to continue to your account.</p>
        </header>

        <?php if ($error !== null): ?>
            <div class="notice notice-error" role="alert"><?= e($error) ?></div>
        <?php endif; ?>
        <?php if (is_string($flashError)): ?>
            <div class="notice notice-error" role="alert"><?= e($flashError) ?></div>
        <?php endif; ?>
        <?php if (is_string($flashSuccess)): ?>
            <div class="notice notice-success" role="status"><?= e($flashSuccess) ?></div>
        <?php endif; ?>

        <form method="post" action="login.php" autocomplete="on">
            <?= csrf_field() ?>
            <label for="email">Email address</label>
            <input id="email" name="email" type="email" maxlength="254" autocomplete="email"
                   value="<?= e($email) ?>" required>

            <label for="password">Password</label>
            <input id="password" name="password" type="password" autocomplete="current-password" required>

            <button type="submit">Sign in</button>
        </form>
        <small>For your security, we don't disclose whether the email address or password was incorrect.</small>
        <p>Need an account? <a href="register.php">Create one</a>.</p>
    </section>
</main>
</body>
</html>

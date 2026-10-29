<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

require_guest();

$errors = [];
$name = '';
$email = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!csrf_verify()) {
        http_response_code(403);
        $errors[] = 'Your form session expired. Please reload the page and try again.';
    } else {
        $nameInput = $_POST['name'] ?? '';
        $emailInput = $_POST['email'] ?? '';
        $passwordInput = $_POST['password'] ?? '';
        $confirmInput = $_POST['confirm_password'] ?? '';

        $name = is_string($nameInput) ? trim($nameInput) : '';
        $email = is_string($emailInput) ? trim($emailInput) : '';
        $password = is_string($passwordInput) ? $passwordInput : '';
        $confirmPassword = is_string($confirmInput) ? $confirmInput : '';

        if ($name === '' || strlen($name) > 100) {
            $errors[] = 'Enter a name of no more than 100 characters.';
        }

        if (strlen($email) > 254 || filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            $errors[] = 'Enter a valid email address.';
        }

        $passwordLength = function_exists('mb_strlen')
            ? mb_strlen($password, 'UTF-8')
            : strlen($password);

        if (
            $passwordLength < 10
            || preg_match('/\p{L}/u', $password) !== 1
            || preg_match('/[0-9]/', $password) !== 1
        ) {
            $errors[] = 'Password must be at least 10 characters and include at least one letter and one number.';
        }

        if ($password !== $confirmPassword) {
            $errors[] = 'Passwords do not match.';
        }

        if ($errors === []) {
            $pdo = db();
            $check = $pdo->prepare('SELECT id FROM users WHERE email = :email LIMIT 1');
            $check->execute(['email' => $email]);

            if ($check->fetch() !== false) {
                $errors[] = 'An account with that email address already exists.';
            } else {
                $passwordHash = password_hash($password, PASSWORD_DEFAULT);

                if ($passwordHash === false) {
                    throw new RuntimeException('Unable to secure the password.');
                }

                try {
                    $insert = $pdo->prepare(
                        'INSERT INTO users (name, email, password_hash, last_login_at)
                         VALUES (:name, :email, :password_hash, CURRENT_TIMESTAMP)'
                    );
                    $insert->execute([
                        'name' => $name,
                        'email' => $email,
                        'password_hash' => $passwordHash,
                    ]);
                } catch (PDOException $exception) {
                    $mysqlErrorCode = $exception->errorInfo[1] ?? null;

                    if ($mysqlErrorCode !== 1062) {
                        throw $exception;
                    }

                    $errors[] = 'An account with that email address already exists.';
                }

                if ($errors === []) {
                    session_regenerate_id(true);
                    unset($_SESSION['_csrf_token'], $_SESSION['_old']);
                    $_SESSION['user_id'] = (int) $pdo->lastInsertId();
                    $_SESSION['role'] = 'user';
                    $_SESSION['last_activity_at'] = time();

                    redirect('dashboard.php');
                }
            }
        }
    }

    if ($errors !== []) {
        $_SESSION['_old'] = [
            'name' => $name,
            'email' => $email,
        ];
    }
}

$name = old('name', $name);
$email = old('email', $email);
unset($_SESSION['_old']);

$successMessage = flash('success');
$errorMessage = flash('error');
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Create account</title>
    <link rel="stylesheet" href="assets/auth.css">
</head>
<body>
<main class="auth-page">
    <section class="auth-card" aria-labelledby="register-title">
        <header class="auth-header">
            <p class="eyebrow">SWD Auth</p>
            <h1 id="register-title">Create your account</h1>
            <p>Register to continue to your dashboard.</p>
        </header>

        <?php if (is_string($successMessage)): ?>
            <div class="notice notice-success" role="status"><?= e($successMessage) ?></div>
        <?php endif; ?>
        <?php if (is_string($errorMessage)): ?>
            <div class="notice notice-error" role="alert"><?= e($errorMessage) ?></div>
        <?php endif; ?>

        <?php if ($errors !== []): ?>
            <div class="notice notice-error" role="alert">
                <p>Please review the following:</p>
                <ul>
                    <?php foreach ($errors as $error): ?>
                        <li><?= e($error) ?></li>
                    <?php endforeach; ?>
                </ul>
            </div>
        <?php endif; ?>

        <form method="post" action="register.php" autocomplete="on">
            <?= csrf_field() ?>
            <label for="name">Name</label>
            <input id="name" name="name" type="text" maxlength="100" autocomplete="name"
                   value="<?= e($name) ?>" required>

            <label for="email">Email address</label>
            <input id="email" name="email" type="email" maxlength="254" autocomplete="email"
                   value="<?= e($email) ?>" required>

            <label for="password">Password</label>
            <input id="password" name="password" type="password" autocomplete="new-password"
                   aria-describedby="password-hint" required>
            <small id="password-hint">At least 10 characters, including a letter and a number.</small>

            <label for="confirm_password">Confirm password</label>
            <input id="confirm_password" name="confirm_password" type="password"
                   autocomplete="new-password" required>

            <button type="submit">Create account</button>
        </form>
        <p>Already have an account? <a href="login.php">Sign in</a>.</p>
    </section>
</main>
</body>
</html>

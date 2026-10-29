<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

require_login();

$user = current_user();
$errors = [];
$successMessage = flash('success');
$name = (string) $user['name'];
$email = (string) $user['email'];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $formInput = $_POST['form'] ?? null;

    if (!csrf_verify()) {
        http_response_code(403);
        $errors[] = 'Your form session expired. Please reload the page and try again.';
    } elseif ($formInput === 'profile') {
        $nameInput = $_POST['name'] ?? '';
        $emailInput = $_POST['email'] ?? '';
        $name = is_string($nameInput) ? trim($nameInput) : '';
        $email = is_string($emailInput) ? trim($emailInput) : '';

        if ($name === '' || strlen($name) > 100) {
            $errors[] = 'Enter a name of no more than 100 characters.';
        }

        if (strlen($email) > 254 || filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            $errors[] = 'Enter a valid email address.';
        }

        if ($errors === []) {
            $duplicate = db()->prepare(
                'SELECT id FROM users WHERE email = :email AND id <> :id LIMIT 1'
            );
            $duplicate->execute([
                'email' => $email,
                'id' => $user['id'],
            ]);

            if ($duplicate->fetch() !== false) {
                $errors[] = 'An account with that email address already exists.';
            } else {
                try {
                    $update = db()->prepare(
                        'UPDATE users SET name = :name, email = :email WHERE id = :id'
                    );
                    $update->execute([
                        'name' => $name,
                        'email' => $email,
                        'id' => $user['id'],
                    ]);
                } catch (PDOException $exception) {
                    if (($exception->errorInfo[1] ?? null) !== 1062) {
                        throw $exception;
                    }

                    $errors[] = 'An account with that email address already exists.';
                }

                if ($errors === []) {
                    flash('success', 'Your profile has been updated.');
                    redirect('profile.php');
                }
            }
        }
    } elseif ($formInput === 'password') {
        $currentPasswordInput = $_POST['current_password'] ?? '';
        $newPasswordInput = $_POST['new_password'] ?? '';
        $confirmPasswordInput = $_POST['confirm_password'] ?? '';
        $currentPassword = is_string($currentPasswordInput) ? $currentPasswordInput : '';
        $newPassword = is_string($newPasswordInput) ? $newPasswordInput : '';
        $confirmPassword = is_string($confirmPasswordInput) ? $confirmPasswordInput : '';

        $passwordStatement = db()->prepare('SELECT password_hash FROM users WHERE id = :id LIMIT 1');
        $passwordStatement->execute(['id' => $user['id']]);
        $passwordRecord = $passwordStatement->fetch();

        if (
            $passwordRecord === false
            || !is_string($passwordRecord['password_hash'])
            || !password_verify($currentPassword, $passwordRecord['password_hash'])
        ) {
            $errors[] = 'The current password is incorrect.';
        }

        $passwordLength = function_exists('mb_strlen')
            ? mb_strlen($newPassword, 'UTF-8')
            : strlen($newPassword);

        if (
            $passwordLength < 10
            || preg_match('/\p{L}/u', $newPassword) !== 1
            || preg_match('/[0-9]/', $newPassword) !== 1
        ) {
            $errors[] = 'New password must be at least 10 characters and include at least one letter and one number.';
        }

        if ($newPassword !== $confirmPassword) {
            $errors[] = 'New passwords do not match.';
        }

        if ($errors === []) {
            $passwordHash = password_hash($newPassword, PASSWORD_DEFAULT);

            if ($passwordHash === false) {
                throw new RuntimeException('Unable to secure the password.');
            }

            if (!session_regenerate_id(true)) {
                throw new RuntimeException('Unable to renew the session.');
            }

            $updatePassword = db()->prepare(
                'UPDATE users SET password_hash = :password_hash WHERE id = :id'
            );
            $updatePassword->execute([
                'password_hash' => $passwordHash,
                'id' => $user['id'],
            ]);

            unset($_SESSION['_csrf_token']);
            flash('success', 'Your password has been changed.');
            redirect('profile.php');
        }
    } else {
        http_response_code(400);
        $errors[] = 'Choose a valid profile form.';
    }
}
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Your profile</title>
    <link rel="stylesheet" href="assets/auth.css">
</head>
<body>
<?php render_navbar(); ?>
<main class="auth-page">
    <section class="auth-card" aria-labelledby="profile-title">
        <header class="auth-header">
            <p class="eyebrow">Account</p>
            <h1 id="profile-title">Your profile</h1>
            <p>Update your account details or change your password.</p>
        </header>

        <?php if (is_string($successMessage)): ?>
            <div class="notice notice-success" role="status"><?= e($successMessage) ?></div>
        <?php endif; ?>
        <?php if ($errors !== []): ?>
            <div class="notice notice-error" role="alert">
                <ul>
                    <?php foreach ($errors as $error): ?>
                        <li><?= e($error) ?></li>
                    <?php endforeach; ?>
                </ul>
            </div>
        <?php endif; ?>

        <h2>Account details</h2>
        <form method="post" action="profile.php" autocomplete="on">
            <?= csrf_field() ?>
            <input type="hidden" name="form" value="profile">
            <label for="name">Name</label>
            <input id="name" name="name" type="text" maxlength="100" autocomplete="name"
                   value="<?= e($name) ?>" required>

            <label for="email">Email address</label>
            <input id="email" name="email" type="email" maxlength="254" autocomplete="email"
                   value="<?= e($email) ?>" required>

            <button type="submit">Save profile</button>
        </form>

        <h2>Change password</h2>
        <form method="post" action="profile.php" autocomplete="on">
            <?= csrf_field() ?>
            <input type="hidden" name="form" value="password">
            <label for="current_password">Current password</label>
            <input id="current_password" name="current_password" type="password"
                   autocomplete="current-password" required>

            <label for="new_password">New password</label>
            <input id="new_password" name="new_password" type="password"
                   autocomplete="new-password" aria-describedby="password-hint" required>
            <small id="password-hint">At least 10 characters, including a letter and a number.</small>

            <label for="confirm_password">Confirm new password</label>
            <input id="confirm_password" name="confirm_password" type="password"
                   autocomplete="new-password" required>

            <button type="submit">Change password</button>
        </form>
    </section>
</main>
</body>
</html>

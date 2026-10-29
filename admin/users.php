<?php
declare(strict_types=1);

require_once dirname(__DIR__) . '/bootstrap.php';

require_role('admin');

$notice = null;
$noticeClass = 'notice-error';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!csrf_verify()) {
        http_response_code(403);
        $notice = 'Your form session expired. Reload the page before trying again.';
    } else {
        $userIdInput = $_POST['user_id'] ?? null;
        $roleInput = $_POST['role'] ?? null;
        $userId = is_string($userIdInput)
            ? filter_var($userIdInput, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]])
            : false;
        $currentUser = current_user();

        if ($userId === false || !is_string($roleInput) || !in_array($roleInput, ['user', 'admin'], true)) {
            http_response_code(400);
            $notice = 'Choose a valid user and role.';
        } elseif ((int) $userId === (int) $currentUser['id'] && $roleInput !== 'admin') {
            $notice = 'You cannot remove your own administrator role.';
        } else {
            $lookup = db()->prepare('SELECT id, role FROM users WHERE id = :id LIMIT 1');
            $lookup->execute(['id' => $userId]);
            $targetUser = $lookup->fetch();

            if ($targetUser === false) {
                http_response_code(404);
                $notice = 'That user could not be found.';
            } elseif ($targetUser['role'] === $roleInput) {
                $noticeClass = 'notice-success';
                $notice = 'That user already has the selected role.';
            } else {
                $update = db()->prepare('UPDATE users SET role = :role WHERE id = :id');
                $update->execute([
                    'role' => $roleInput,
                    'id' => $userId,
                ]);
                flash('success', 'Updated ' . (string) $targetUser['role'] . ' to ' . $roleInput . '.');
                redirect('users.php');
            }
        }
    }
}

$successMessage = flash('success');
$users = db()->query(
    'SELECT id, name, email, role, created_at, last_login_at
     FROM users
     ORDER BY name, id'
)->fetchAll();
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Manage users</title>
    <link rel="stylesheet" href="../assets/auth.css">
</head>
<body>
<?php render_navbar(); ?>
<main class="auth-page">
    <section class="auth-card auth-card-wide" aria-labelledby="users-title">
        <header class="auth-header">
            <p class="eyebrow">Admin</p>
            <h1 id="users-title">Manage users</h1>
            <p>Review accounts and update their roles.</p>
        </header>

        <?php if (is_string($successMessage)): ?>
            <div class="notice notice-success" role="status"><?= e($successMessage) ?></div>
        <?php endif; ?>
        <?php if ($notice !== null): ?>
            <div class="notice <?= e($noticeClass) ?>" role="alert"><?= e($notice) ?></div>
        <?php endif; ?>

        <div class="table-wrap">
            <table>
                <thead>
                <tr>
                    <th scope="col">Name</th>
                    <th scope="col">Email</th>
                    <th scope="col">Role</th>
                    <th scope="col">Created</th>
                    <th scope="col">Last login</th>
                </tr>
                </thead>
                <tbody>
                <?php foreach ($users as $user): ?>
                    <tr>
                        <td><?= e((string) $user['name']) ?></td>
                        <td><?= e((string) $user['email']) ?></td>
                        <td>
                            <form method="post" action="users.php">
                                <?= csrf_field() ?>
                                <input type="hidden" name="user_id" value="<?= e((string) $user['id']) ?>">
                                <select name="role" aria-label="Role for <?= e((string) $user['email']) ?>">
                                    <option value="user" <?= $user['role'] === 'user' ? 'selected' : '' ?>>User</option>
                                    <option value="admin" <?= $user['role'] === 'admin' ? 'selected' : '' ?>>Admin</option>
                                </select>
                                <button type="submit">Save</button>
                            </form>
                        </td>
                        <td><?= e((string) $user['created_at']) ?></td>
                        <td><?= is_string($user['last_login_at']) ? e($user['last_login_at']) : 'Never' ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </section>
</main>
</body>
</html>

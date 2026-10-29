<?php
declare(strict_types=1);

function render_navbar(): void
{
    $user = current_user();
    $basePath = basename(dirname($_SERVER['SCRIPT_NAME'] ?? '')) === 'admin' ? '../' : '';
    ?>
    <nav class="site-nav" aria-label="Main navigation">
        <a class="site-brand" href="<?= e($basePath) ?>dashboard.php">SWD Auth</a>
        <?php if ($user !== null): ?>
            <div class="site-nav-links">
                <a href="<?= e($basePath) ?>dashboard.php">Dashboard</a>
                <a href="<?= e($basePath) ?>profile.php">Profile</a>
                <?php if ($user['role'] === 'admin'): ?>
                    <a href="<?= e($basePath) ?>admin/users.php">Admin</a>
                <?php endif; ?>
            </div>
        <?php endif; ?>
    </nav>
    <?php
}

<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Allow: POST');
    http_response_code(405);
    exit('Method not allowed.');
}

if (!csrf_verify()) {
    http_response_code(403);
    exit('Your form session expired. Please reload the page and try again.');
}

end_session();
flash('success', 'You have been signed out.');
redirect('login.php');

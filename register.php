<?php
session_start();
require_once 'config/database.php';

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$message = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $token = $_POST['csrf_token'] ?? '';
    $username = trim($_POST['username'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $password = trim($_POST['password'] ?? '');
    $confirm = trim($_POST['confirm'] ?? '');

    if (!hash_equals($_SESSION['csrf_token'], $token)) {
        $message = 'Invalid request (CSRF). Please reload the page and try again.';
    } elseif ($username === '' || $email === '' || $password === '' || $confirm === '') {
        $message = 'Please fill in all fields.';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $message = 'Please enter a valid email address.';
    } elseif ($password !== $confirm) {
        $message = 'Passwords do not match.';
    } else {
        try {
            $sql = "SELECT id FROM users WHERE username = :username OR email = :email";
            $stmt = $pdo->prepare($sql);
            $stmt->bindParam(':username', $username, PDO::PARAM_STR);
            $stmt->bindParam(':email', $email, PDO::PARAM_STR);
            $stmt->execute();
            if ($stmt->rowCount() > 0) {
                $message = 'Username or email already exists.';
            } else {
                $hash = password_hash($password, PASSWORD_DEFAULT);
                $sql = "INSERT INTO users (username, email, password) VALUES (:username, :email, :password)";
                $stmt = $pdo->prepare($sql);
                $stmt->bindParam(':username', $username, PDO::PARAM_STR);
                $stmt->bindParam(':email', $email, PDO::PARAM_STR);
                $stmt->bindParam(':password', $hash, PDO::PARAM_STR);
                $stmt->execute();
                $message = 'Registration successful! You can now log in.';
            }
        } catch(PDOException $e) {
            $message = 'Something went wrong. Please try again later.';
        }
    }
}
?>
<!doctype html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width,initial-scale=1">
	<title>Register — ThriveTrack</title>
	<link rel="stylesheet" href="style.css">
</head>
<body>
	<div class="wrap">
		<main class="card" role="main">
			<h1>Create your account</h1>

			<?php if ($message): ?>
				<div class="msg" role="alert"><?php echo htmlspecialchars($message); ?></div>
			<?php endif; ?>

			<form method="post" action="" autocomplete="on" novalidate>
				<input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">

				<div>
					<label for="username">Username</label>
					<input id="username" name="username" type="text" autocomplete="username" required>
				</div>

				<div>
					<label for="email">Email</label>
					<input id="email" name="email" type="email" autocomplete="email" required>
				</div>

				<div>
					<label for="password">Password</label>
					<input id="password" name="password" type="password" autocomplete="new-password" required>
				</div>

				<div>
					<label for="confirm">Confirm Password</label>
					<input id="confirm" name="confirm" type="password" autocomplete="new-password" required>
				</div>

				<div class="row">
					<button type="submit" class="primary">Register</button>
				</div>

				<div class="meta">
					Already have an account? <a class="link" href="login.php">Login</a>
				</div>
			</form>
		</main>
	</div>
</body>
</html>

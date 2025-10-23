<?php
session_start();
require_once 'config/database.php';

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$message = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	$token = $_POST['csrf_token'] ?? '';
	$email = trim($_POST['email'] ?? '');

	if (!hash_equals($_SESSION['csrf_token'], $token)) {
		$message = 'Invalid request (CSRF). Please reload the page and try again.';
	} elseif ($email === '') {
		$message = 'Please enter your email address.';
	} elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
		$message = 'Please enter a valid email address.';
	} else {
		try {
			$sql = "SELECT id FROM users WHERE email = :email";
			$stmt = $pdo->prepare($sql);
			$stmt->bindParam(':email', $email, PDO::PARAM_STR);
			$stmt->execute();
			if ($stmt->rowCount() > 0) {
				$row = $stmt->fetch();
				$user_id = $row['id'];
				$reset_token = bin2hex(random_bytes(32));
				$expires = date('Y-m-d H:i:s', time() + 3600);
				$sql = "UPDATE users SET reset_token = :token, reset_expires = :expires WHERE id = :id";
				$stmt2 = $pdo->prepare($sql);
				$stmt2->bindParam(':token', $reset_token, PDO::PARAM_STR);
				$stmt2->bindParam(':expires', $expires, PDO::PARAM_STR);
				$stmt2->bindParam(':id', $user_id, PDO::PARAM_INT);
				$stmt2->execute();
				$reset_link = "http://" . $_SERVER['HTTP_HOST'] . dirname($_SERVER['PHP_SELF']) . "/resetpass.php?token=$reset_token";
				$message = 'A password reset link has been generated:<br><a href="' . htmlspecialchars($reset_link) . '">' . htmlspecialchars($reset_link) . '</a><br>(In production, this would be emailed to you.)';
			} else {
				$message = 'If your email is registered, you will receive a password reset link.';
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
	<title>Forgot Password — ThriveTrack</title>
	<link rel="stylesheet" href="style.css">
</head>
<body>
	<div class="wrap">
		<main class="card" role="main">
			<h1>Forgot your password?</h1>

			<?php if ($message): ?>
				<div class="msg" role="alert"><?php echo htmlspecialchars($message); ?></div>
			<?php endif; ?>

			<form method="post" action="" autocomplete="on" novalidate>
				<input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">

				<div>
					<label for="email">Email</label>
					<input id="email" name="email" type="email" autocomplete="email" required>
				</div>

				<div class="row">
					<button type="submit" class="primary">Send Reset Link</button>
				</div>

				<div class="meta">
					Remembered your password? <a class="link" href="login.php">Login</a>
				</div>
			</form>
		</main>
	</div>
</body>
</html>

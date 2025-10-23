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
    $password = trim($_POST['password'] ?? '');

    if (!hash_equals($_SESSION['csrf_token'], $token)) {
        $message = 'Invalid request (CSRF). Please reload the page and try again.';
    } elseif ($username === '' || $password === '') {
        $message = 'Please enter both username and password.';
    } else {
        try {
            $sql = "SELECT id, username, password FROM users WHERE username = :username";
            $stmt = $pdo->prepare($sql);

            $stmt->bindParam(':username', $username, PDO::PARAM_STR);

            $stmt->execute();
            
            if ($stmt->rowCount() == 1) {
                $row = $stmt->fetch();
                if (password_verify($password, $row['password'])) {
                    session_regenerate_id();
                    
                    $_SESSION['user_id'] = $row['id'];
                    $_SESSION['username'] = $row['username'];
                    
                    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                    
                    header('Location: dashboard.php');
                    exit();
                } else {
                    $message = 'Invalid username or password.';
                }
            } else {
                $message = 'Invalid username or password.';
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
	<title>Login — ThriveTrack</title>
	<link rel="stylesheet" href="style.css">
</head>
<body>
	<div class="wrap">
		<main class="card" role="main">
			<h1>Welcome to <strong>THRIVE<span class="highlight">TRACK</span></strong>!</h1>

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
					<label for="password">Password</label>
					<input id="password" name="password" type="password" autocomplete="current-password" required>
				</div>

				<div class="row">
					<div class="actions">
						<button type="submit" class="primary">Sign in</button>
						<button type="button" id="togglePwd" title="Show password">Show</button>
					</div>
					<div>
						<a class="link" href="forgot_password.php">Forgot Password?</a>
					</div>
				</div>

				<div class="meta">
					Don't have an account? <a class="link" href="register.php">Register</a>
				</div>
			</form>
		</main>
	</div>

	<script>
		(function(){
			var btn = document.getElementById('togglePwd');
			var pwd = document.getElementById('password');
			btn.addEventListener('click', function(){
				if (pwd.type === 'password') { pwd.type = 'text'; btn.textContent = 'Hide'; }
				else { pwd.type = 'password'; btn.textContent = 'Show'; }
			});
		})();
	</script>
</body>
</html>


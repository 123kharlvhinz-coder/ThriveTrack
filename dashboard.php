<?php
session_start();

if (empty($_SESSION['username'])) {
    header('Location: login.php');
    exit;
}
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Dashboard — ThriveTrack</title>
    <link rel="stylesheet" href="style.css">
    <link rel="stylesheet" href="dashboard.css">
</head>
<body>
    <div class="full-bleed">
        <main class="dashboard-card">
            <div class="dashboard-topbar">
                <h1><strong>THRIVE<span class="highlight">TRACK</span></strong></h1>
                <nav class="top-nav" role="navigation" aria-label="Main">
                    <ul class="nav">
                        <li class="nav-item"><a class="nav-link" href="#">WELLNESS</a></li>
                        <li class="nav-item"><a class="nav-link" href="#">FITNESS</a></li>
                        <li class="nav-item"><a class="nav-link" href="#">SOCIALS</a></li>
                    </ul>
                </nav>
                <div class="user-section">
                    <div class="welcome">Welcome, <?php echo htmlspecialchars($_SESSION['username']); ?>!</div>

                    <div class="account">
                        <button id="accountBtn" class="avatar-btn" aria-haspopup="true" aria-expanded="false" aria-controls="accountMenu">
                            <span class="avatar"><?php echo strtoupper(substr(htmlspecialchars($_SESSION['username']),0,1)); ?></span>
                        </button>

                        <ul id="accountMenu" class="dropdown-menu" role="menu" aria-hidden="true">
                            <li role="none"><a role="menuitem" class="dropdown-item" href="profile.php">Profile</a></li>
                            <li role="none"><a role="menuitem" class="dropdown-item" href="settings.php">Settings</a></li>
                            <li role="none"><a role="menuitem" class="dropdown-item" href="logout.php">Logout</a></li>
                        </ul>
                    </div>
                </div>
            </div>

            <div class="main-area">
            </div>
        </main>
    </div>
            </div>
        </main>
    </div>
</body>
</html>

<script>
    (function(){
        var btn = document.getElementById('accountBtn');
        var menu = document.getElementById('accountMenu');
        if (!btn || !menu) return;
        btn.addEventListener('click', function(e){
            var expanded = btn.getAttribute('aria-expanded') === 'true';
            btn.setAttribute('aria-expanded', !expanded);
            menu.setAttribute('aria-hidden', expanded);
        });

        document.addEventListener('click', function(e){
            if (!menu.contains(e.target) && !btn.contains(e.target)){
                btn.setAttribute('aria-expanded', 'false');
                menu.setAttribute('aria-hidden', 'true');
            }
        });
    })();
</script>
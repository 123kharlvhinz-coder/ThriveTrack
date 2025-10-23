<?php
require_once 'config/database.php';

try {
    $username = "testuser";
    $password = password_hash("testpass123", PASSWORD_DEFAULT);
    $email = "test@example.com";
    
    $sql = "INSERT INTO users (username, password, email) VALUES (:username, :password, :email)";
    $stmt = $pdo->prepare($sql);
    
    $stmt->bindParam(':username', $username);
    $stmt->bindParam(':password', $password);
    $stmt->bindParam(':email', $email);
    
    $stmt->execute();
    
    echo "Test user created successfully!";
    echo "\nUsername: testuser";
    echo "\nPassword: testpass123";
    
} catch(PDOException $e) {
    die("Error: " . $e->getMessage());
}
?>
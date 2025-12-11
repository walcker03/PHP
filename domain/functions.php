<?php
require_once 'db.php';

/**
 * Валидация цвета в формате HEX
 */
function isValidColor($color) {
    return preg_match('/^#[a-f0-9]{6}$/i', $color);
}

/**
 * Генерация CSRF токена
 */
function generateCsrfToken() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/**
 * Проверка CSRF токена
 */
function verifyCsrfToken($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

/**
 * Автоматическая авторизация по токену из cookie
 */
function autoLogin($pdo) {
    if (!isset($_SESSION['user_id']) && isset($_COOKIE['token'])) {
        $stmt = $pdo->prepare("SELECT * FROM users WHERE token = ?");
        $stmt->execute([$_COOKIE['token']]);
        if ($user = $stmt->fetch()) {
            $_SESSION['user_id'] = $user['id'];
            setcookie('bg_color', $user['bg_color'], time() + 3600 * 24 * 7, "/");
            setcookie('text_color', $user['text_color'], time() + 3600 * 24 * 7, "/");
        }
    }
}

/**
 * Регистрация нового пользователя
 */
function registerUser($pdo, $username, $password, $bg_color, $text_color) {
    // Валидация входных данных
    $username = trim($username);
    if (strlen($username) < 3) {
        return "Логин должен быть не менее 3 символов";
    }
    
    if (strlen($password) < 6) {
        return "Пароль должен быть не менее 6 символов";
    }
    
    if (!isValidColor($bg_color) || !isValidColor($text_color)) {
        return "Некорректный формат цвета";
    }
    
    $passwordHash = password_hash($password, PASSWORD_DEFAULT);
    
    // Используем правильные названия колонок
    $stmt = $pdo->prepare("INSERT INTO users (username, password_hash, bg_color, text_color) VALUES (?, ?, ?, ?)");
    
    try {
        $stmt->execute([$username, $passwordHash, $bg_color, $text_color]);
        return true;
    } catch (PDOException $e) {
        return "Пользователь с таким логином уже существует";
    }
}

/**
 * Авторизация пользователя
 */
function loginUser($pdo, $username, $password) {
    $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
    $stmt->execute([trim($username)]);
    
    if ($user = $stmt->fetch()) {
        // Проверяем пароль против password_hash
        if (password_verify($password, $user['password_hash'])) {
            $token = bin2hex(random_bytes(16));
            $_SESSION['user_id'] = $user['id'];

            // ИСПРАВЛЕННЫЙ синтаксис setcookie - используем отдельные параметры
            setcookie('token', $token, time() + 3600 * 24 * 7, "/", "", false, true); // httponly=true
            setcookie('bg_color', $user['bg_color'], time() + 3600 * 24 * 7, "/");
            setcookie('text_color', $user['text_color'], time() + 3600 * 24 * 7, "/");

            // Обновляем токен в базе
            $upd = $pdo->prepare("UPDATE sessions SET token = ? WHERE id = ?");
            $upd->execute([$token, $user['id']]);

            return true;
        }
    }
    return false;
}

/**
 * Обновление настроек пользователя
 */
function updateSettings($pdo, $userId, $bg_color, $text_color) {
    if (!isValidColor($bg_color) || !isValidColor($text_color)) {
        return "Некорректный формат цвета";
    }
    
    $stmt = $pdo->prepare("UPDATE users SET bg_color = ?, text_color = ? WHERE id = ?");
    $stmt->execute([$bg_color, $text_color, $userId]);

    setcookie('bg_color', $bg_color, time() + 3600 * 24 * 7, "/");
    setcookie('text_color', $text_color, time() + 3600 * 24 * 7, "/");
    
    return true;
}

/**
 * Логаут пользователя
 */
function logoutUser($pdo) {
    if (isset($_COOKIE['token'])) {
        $stmt = $pdo->prepare("UPDATE sessions SET token = NULL WHERE token = ?");
        $stmt->execute([$_COOKIE['token']]);
    }
    
    setcookie('token', '', time() - 3600, "/");
    setcookie('bg_color', '', time() - 3600, "/");
    setcookie('text_color', '', time() - 3600, "/");
    
    session_destroy();
}

/**
 * Получение текущего пользователя
 */
function getCurrentUser($pdo) {
    if (isset($_SESSION['user_id'])) {
        $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->execute([$_SESSION['user_id']]);
        return $stmt->fetch();
    }
    return null;
}
?>
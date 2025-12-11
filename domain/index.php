<?php
require_once 'db.php';
require_once 'functions.php';

// Автоавторизация
autoLogin($pdo);

// Генерация CSRF токена
$csrfToken = generateCsrfToken();

// Переменные для уведомлений
$message = '';
$messageType = ''; // 'success' или 'error'

// Обработка POST запросов
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Проверка CSRF токена
    if (!verifyCsrfToken($_POST['csrf_token'] ?? '')) {
        $message = "Ошибка безопасности";
        $messageType = 'error';
    } else {
        switch ($_POST['action']) {
            case 'register':
                $result = registerUser(
                    $pdo,
                    $_POST['username'] ?? '',
                    $_POST['password'] ?? '',
                    $_POST['bg_color'] ?? '#ffffff',
                    $_POST['text_color'] ?? '#000000'
                );
                
                if ($result === true) {
                    $message = "Регистрация успешна! Теперь вы можете войти.";
                    $messageType = 'success';
                } else {
                    $message = $result;
                    $messageType = 'error';
                }
                break;

            case 'login':
                if (loginUser($pdo, $_POST['username'] ?? '', $_POST['password'] ?? '')) {
                    header("Location: index.php");
                    exit;
                } else {
                    $message = "Неверный логин или пароль";
                    $messageType = 'error';
                }
                break;

            case 'update':
                $result = updateSettings(
                    $pdo,
                    $_SESSION['user_id'],
                    $_POST['bg_color'] ?? '#ffffff',
                    $_POST['text_color'] ?? '#000000'
                );
                
                if ($result === true) {
                    header("Location: index.php");
                    exit;
                } else {
                    $message = $result;
                    $messageType = 'error';
                }
                break;
        }
    }
}

// Обработка выхода
if (isset($_GET['logout'])) {
    logoutUser($pdo);
    header("Location: index.php");
    exit;
}

// Получение данных текущего пользователя
$user = getCurrentUser($pdo);
$bg = $_COOKIE['bg_color'] ?? '#ffffff';
$font = $_COOKIE['text_color'] ?? '#000000';
?>
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Авторизация / Регистрация</title>
    <style>
        body {
            background-color: <?= htmlspecialchars($bg) ?>;
            color: <?= htmlspecialchars($font) ?>;
            font-family: Arial, sans-serif;
            margin: 40px;
            transition: background-color 0.3s, color 0.3s;
        }
        form { 
            margin-bottom: 20px; 
            padding: 20px;
            border: 1px solid #ddd;
            border-radius: 5px;
            max-width: 300px;
        }
        input, button {
            margin: 5px 0;
            padding: 8px;
            width: 100%;
            box-sizing: border-box;
        }
        .message {
            padding: 10px;
            margin: 10px 0;
            border-radius: 5px;
        }
        .success {
            background-color: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        .error {
            background-color: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
    </style>
</head>
<body>

<?php if ($message): ?>
    <div class="message <?= $messageType ?>">
        <?= htmlspecialchars($message) ?>
    </div>
<?php endif; ?>

<?php if (!$user): ?>
    <h2>Вход</h2>
    <form method="POST">
        <input type="hidden" name="action" value="login">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
        <input type="text" name="username" placeholder="Логин" minlength="3" required>
        <input type="password" name="password" placeholder="Пароль" minlength="6" required>
        <button type="submit">Войти</button>
    </form>

    <h2>Регистрация</h2>
    <form method="POST">
        <input type="hidden" name="action" value="register">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
        <input type="text" name="username" placeholder="Логин" minlength="3" required>
        <input type="password" name="password" placeholder="Пароль" minlength="6" required>
        <label>Фон:</label>
        <input type="color" name="bg_color" value="#ffffff">
        <label>Цвет шрифта:</label>
        <input type="color" name="text_color" value="#000000">
        <button type="submit">Зарегистрироваться</button>
    </form>

<?php else: ?>
    <h1>Здравствуйте, <?= htmlspecialchars($user['username']) ?>!</h1>
    <a href="?logout=1">Выйти</a>

    <hr>
    <h2>Настройки внешнего вида</h2>
    <form method="POST">
        <input type="hidden" name="action" value="update">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
        <label>Фон:</label>
        <input type="color" name="bg_color" value="<?= htmlspecialchars($user['bg_color']) ?>">
        <label>Цвет шрифта:</label>
        <input type="color" name="text_color" value="<?= htmlspecialchars($user['text_color']) ?>">
        <button type="submit">Сохранить настройки</button>
    </form>
<?php endif; ?>

</body>
</html>
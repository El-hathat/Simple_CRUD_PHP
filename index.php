<?php
session_start();


if (isset($_SESSION['email'])) {
  
    header('Location: page1.php');
    exit();
}


if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['email']) && isset($_POST['password'])) {
    $email = $_POST['email'];
    $password = $_POST['password'];

    $pdo = new PDO("mysql:host=localhost;dbname=enset-a", 'root', '');

    $stmt = $pdo->prepare("SELECT * FROM users WHERE email = :email");

    $stmt->execute(['email' => $email]);

    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user && password_verify($password, $user['password']) && $user['role'] === 'admin') {
        $_SESSION['email'] = $user['email'];
        header('Location: page1.php');
        exit();
    } else {
        $error = "Adresse e-mail ou mot de passe incorrect.";
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authentification</title>
</head>
<body>
    <div class="container mt-5">
        <h2>Connexion</h2>
        <?php if (isset($error)): ?>
            <div class="alert alert-danger" role="alert">
                <?= $error ?>
            </div>
        <?php endif ?>
        <form method="post">
            <div class="form-group">
                <label for="email">Adresse E-mail:</label>
                <input type="email" class="form-control" id="email" name="email" required>
            </div>
            <div class="form-group">
                <label for="password">Mot de passe:</label>
                <input type="password" class="form-control" id="password" name="password" required>
            </div>
            <button type="submit" class="btn btn-primary">Se connecter</button>
        </form>
    </div>
</body>
</html>


<?php
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['email']) && isset($_POST['pass']) && isset($_POST['role'])) {
    $email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
    $pass = password_hash($_POST['pass'], PASSWORD_DEFAULT);
    $role = $_POST['role'];

    $pdo = new PDO("mysql:dbname=enset-a", 'root', '');
    $stmt = $pdo->prepare("INSERT INTO users (email, password, role) VALUES (?, ?, ?)");
    $stmt->execute([$email, $pass, $role]);

    header('Location: index.php');
    exit();
}

if (isset($_GET['idd'])) {
    $id = $_GET['idd'];

    $pdo = new PDO("mysql:dbname=enset-a", 'root', '');
    $sql = "SELECT * FROM users WHERE id=:id";
    $stmt = $pdo->prepare($sql);
    $stmt->execute(['id' => $id]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        header('Location: index.php');
        exit();
    }
}

if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['id'])) {
    $id = $_POST['id'];
    $email = $_POST['email'];
    $role = $_POST['role'];

    if (!empty($_POST['pass'])) {
        $pass = password_hash($_POST['pass'], PASSWORD_DEFAULT);
        $updatePassword = ", password=:password";
    } else {
        $updatePassword = "";
    }

    $pdo = new PDO("mysql:dbname=enset-a", 'root', '');
    $sql = "UPDATE users SET email=:email, role=:role $updatePassword WHERE id=:id";
    $stmt = $pdo->prepare($sql);
    $stmt->bindParam(':email', $email);
    $stmt->bindParam(':role', $role);
    $stmt->bindParam(':id', $id);
    if (!empty($_POST['pass'])) {
        $stmt->bindParam(':password', $pass);
    }
    $stmt->execute();

    header('Location: index.php');
    exit();
}

if (isset($_GET['idd'])) {
    $id = $_GET['idd'];

    $pdo = new PDO("mysql:dbname=enset-a", 'root', '');
    $sql = "DELETE FROM users WHERE id=:id";
    $stmt = $pdo->prepare($sql);
    $stmt->bindParam(':id', $id);
    $stmt->execute();

    header('Location: index.php');
    exit();
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SGBD MySQL</title>
</head>

<body>
    <div class="container mt-3">
        <h1>Add User</h1>
        <form action="index.php" method="post">
            <input type="text" class="form-control mb-2" name="email" placeholder="Email">
            <input type="password" class="form-control mb-2" name="pass" placeholder="Password">
            <select name="role" class="form-select mb-2">
                <option value="guest">Guest</option>
                <option value="admin">Admin</option>
                <option value="editor">Editor</option>
            </select>
            <button class="btn btn-primary mb-4 w-100">Add</button>
        </form>

        <?php if (isset($user)): ?>
            <h1>Edit User</h1>
            <form action="index.php" method="post">
                <input type="hidden" name="id" value="<?= $user['id'] ?>">
                <input type="text" class="form-control mb-2" name="email" placeholder="Email" value="<?= $user["email"] ?>">
                <input type="password" class="form-control mb-2" name="pass" placeholder="New Password">
                <select name="role" class="form-select mb-2">
                    <option value="guest" <?= $user['role'] === 'guest' ? 'selected' : '' ?>>Guest</option>
                    <option value="admin" <?= $user['role'] === 'admin' ? 'selected' : '' ?>>Admin</option>
                    <option value="editor" <?= $user['role'] === 'editor' ? 'selected' : '' ?>>Editor</option>
                </select>
                <button class="btn btn-primary mb-4 w-100">Save Changes</button>
            </form>
        <?php endif ?>

        <h1>User List</h1>
        <table class="table table-striped table-hover table-bordered">
            <thead>
                <tr class="text-center">
                    <th>ID</th>
                    <th>Email</th>
                    <th>Password</th>
                    <th>Role</th>
                    <th>Delete</th>
                    <th>Edit</th>
                </tr>
            </thead>
            <tbody>
                <?php
                $pdo = new PDO("mysql:dbname=enset-a", 'root', '');
                $sql = "SELECT * FROM users";
                $stmt = $pdo->query($sql);
                $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
                foreach ($users as $user):
                ?>
                    <tr>
                        <td class="text-center"><?= $user['id'] ?></td>
                        <td><?= $user['email'] ?></td>
                        <td><?= $user['password'] ?></td>
                        <td><?= $user['role'] ?></td>
                        <td class="text-center">
                            <a href="index.php?idd=<?= $user['id'] ?>" class="btn btn-danger" onclick="return confirm('Are you sure you want to delete this user?')">Delete</a>
                        </td>
                        <td class="text-center">
                            <a href="index.php?idd=<?= $user['id'] ?>" class="btn btn-success">Edit</a>
                        </td>
                    </tr>
                <?php endforeach ?>
            </tbody>
        </table>
    </div>
</body>

</html>


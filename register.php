<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Register Page</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<style>
body {
  background: linear-gradient(135deg, #74ebd5 0%, #ACB6E5 100%);
}
.card {
  border-radius: 1rem;
}
.btn-primary {
  background: linear-gradient(90deg, #6a11cb 0%, #2575fc 100%);
  border: none;
}
.btn-primary:hover {
  background: linear-gradient(90deg, #2575fc 0%, #6a11cb 100%);
}
h2 {
  font-weight: bold;
  letter-spacing: 1px;
}
</style>
<body class="bg-light">

<div class="container d-flex flex-column justify-content-center align-items-center min-vh-100">
  <div class="card p-4 shadow" style="max-width: 400px; width: 100%;">
    <h2 class="mb-4 text-center text-primary">Register</h2>

    <?php
    include 'inc/db.php'; // ← Make sure this contains your DB connection

    $username = $email = $password = "";
    $errors = [];
    $success = false;

    if ($_SERVER["REQUEST_METHOD"] == "POST") {
      $username = trim($_POST["username"]);
      $email = trim($_POST["email"]);
      $password = trim($_POST["password"]);

      // Validation
      if (empty($username)) {
        $errors['username'] = "Please enter a username.";
      }
      if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors['email'] = "Please enter a valid email address.";
      }
      if (strlen($password) < 6) {
        $errors['password'] = "Password must be at least 6 characters.";
      }

      // Check for duplicate email
      $stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
      $stmt->bind_param("s", $email);
      $stmt->execute();
      $stmt->store_result();
      if ($stmt->num_rows > 0) {
        $errors['email'] = "Email already registered.";
      }
      $stmt->close();

      // If no errors, insert into database
      if (empty($errors)) {
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
        $role = 'user';

        $stmt = $conn->prepare("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)");
        $stmt->bind_param("ssss", $username, $email, $hashedPassword, $role);

        if ($stmt->execute()) {
          $success = true;
          $username = $email = $password = ""; // Clear form values
        } else {
          $errors['general'] = "Something went wrong. Please try again.";
        }
        $stmt->close();
        $conn->close();
      }
    }
    ?>

    <?php if ($success): ?>
      <div class="alert alert-success">Registration successful!</div>
    <?php endif; ?>
    <?php if (isset($errors['general'])): ?>
      <div class="alert alert-danger"><?php echo $errors['general']; ?></div>
    <?php endif; ?>

    <form method="POST" action="" novalidate>
      <div class="mb-3">
        <label for="username" class="form-label">Username</label>
        <input type="text" class="form-control <?php if(isset($errors['username'])) echo 'is-invalid'; ?>" id="username" name="username" value="<?php echo htmlspecialchars($username); ?>" required>
        <?php if(isset($errors['username'])): ?>
          <div class="invalid-feedback"><?php echo $errors['username']; ?></div>
        <?php endif; ?>
      </div>

      <div class="mb-3">
        <label for="email" class="form-label">Email address</label>
        <input type="email" class="form-control <?php if(isset($errors['email'])) echo 'is-invalid'; ?>" id="email" name="email" value="<?php echo htmlspecialchars($email); ?>" required>
        <?php if(isset($errors['email'])): ?>
          <div class="invalid-feedback"><?php echo $errors['email']; ?></div>
        <?php endif; ?>
      </div>

      <div class="mb-3">
        <label for="password" class="form-label">Password</label>
        <input type="password" class="form-control <?php if(isset($errors['password'])) echo 'is-invalid'; ?>" id="password" name="password" required>
        <?php if(isset($errors['password'])): ?>
          <div class="invalid-feedback"><?php echo $errors['password']; ?></div>
        <?php endif; ?>
      </div>

      <button type="submit" class="btn btn-primary w-100">Register</button>
    </form>
  </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>

<?php
$host = "localhost";
$dbusername = "root";
$dbpassword = "";
$dbname = "e-commerce";

$conn = new mysqli($host, $dbusername, $dbpassword, $dbname);

if (mysqli_connect_error()) {
    die('Connect Error (' . mysqli_connect_errno() . ') ' . mysqli_connect_error());
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Handle Registration
    if (isset($_POST['uname1']) && isset($_POST['email']) && isset($_POST['mobileno']) && isset($_POST['upswd1']) && isset($_POST['upswd2'])) {
        $uname1 = $_POST['uname1'];
        $email = $_POST['email'];
        $mobileno = $_POST['mobileno'];
        $upswd1 = $_POST['upswd1'];
        $upswd2 = $_POST['upswd2'];

        if (!empty($uname1) && !empty($email) && !empty($mobileno) && !empty($upswd1) && !empty($upswd2)) {
            if ($upswd1 !== $upswd2) {
                echo "Passwords do not match";
                die();
            }

            $SELECT = "SELECT email FROM register WHERE email = ? LIMIT 1";
            $INSERT = "INSERT INTO register (uname1, email, mobileno, upswd1) VALUES (?, ?, ?, ?)";
            $stmt = $conn->prepare($SELECT);
            $stmt->bind_param("s", $mobileno);
            $stmt->execute();
            $stmt->store_result();
            $rnum = $stmt->num_rows;

            if ($rnum == 0) {
                $stmt->close();
                // Hash the password before storing it
                $hashed_password = password_hash($upswd1, PASSWORD_DEFAULT);
                $stmt = $conn->prepare($INSERT);
                $stmt->bind_param("ssis", $uname1, $email, $mobileno, $hashed_password);
                $stmt->execute();
                echo "New record inserted successfully";
                echo '<a href="index.html">Go to Home</a>';
            } else {
                echo "Someone already registered using this email";

            }
            $stmt->close();
        } else {
            echo "All fields are required";
            die();
        }
    }
    // Handle Login
    elseif (isset($_POST['uname']) && isset($_POST['upswd'])) {
        $uname = $_POST['uname'];
        $upswd = $_POST['upswd'];

        if (!empty($uname) && !empty($upswd)) {
            $SELECT = "SELECT uname1, upswd1 FROM register WHERE uname1 = ? LIMIT 1";

            $stmt = $conn->prepare($SELECT);
            $stmt->bind_param("s", $uname);
            $stmt->execute();
            $stmt->store_result();
            $stmt->bind_result($db_uname, $db_upswd);
            $stmt->fetch();

            if ($stmt->num_rows == 1 && password_verify($upswd, $db_upswd)) {
                echo "Login successful";
                echo '<a href="index.html">Go to Home</a>';
            } else {
                echo "Invalid username or password";
            }
            $stmt->close();
        } else {
            echo "All fields are required";
            die();
        }
    }
}
$conn->close();
?>
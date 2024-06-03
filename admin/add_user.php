<?php
include("../includes/config.php");
include("../includes/validate_data.php");
session_start();

if (isset($_SESSION['admin_login']) && $_SESSION['admin_login'] == true) {
    $requireErr = $usernameErr = $passwordErr = $matchErr = $otherErr = "";

    if ($_SERVER['REQUEST_METHOD'] == "POST") {
        if (!empty($_POST['txtNewUser']) && !empty($_POST['txtPassword']) && !empty($_POST['txtConfirmPassword']) && isset($_POST['role'])) {
            $username = $_POST['txtNewUser'];
            $password = $_POST['txtPassword'];
            $confirmPassword = $_POST['txtConfirmPassword'];
            $role = $_POST['role'];

            // Validate username and password using validate_data.php
            if (validate_username($username) !== true) {
                $usernameErr = validate_username($username);
            }
            if (validate_password($password) !== true) {
                $passwordErr = validate_password($password);
            }

            if ($password !== $confirmPassword) {
                $matchErr = "* Passwords do not match";
            }

            if (empty($usernameErr) && empty($passwordErr) && empty($matchErr)) {
                // Hash the password
                $password = hash('sha256', $password);

                switch ($role) {
                    case 'admin':
                        $query_addUser = "INSERT INTO admin (username, password) VALUES (?, ?)";
                        $stmt = mysqli_prepare($con, $query_addUser);
                        mysqli_stmt_bind_param($stmt, "ss", $username, $password);
                        break;
                    case 'retailer':
                        $address = $_POST['address'];
                        $area_id = $_POST['area_id'];
                        $phone = $_POST['phone'];
                        $email = $_POST['email'];

                        // Validate additional fields for retailer
                        if (validate_phone($phone) !== true) {
                            $otherErr = validate_phone($phone);
                        }
                        if (validate_email($email) !== true) {
                            $otherErr = validate_email($email);
                        }

                        if (empty($otherErr)) {
                            $query_addUser = "INSERT INTO retailer (username, password, address, area_id, phone, email) VALUES (?, ?, ?, ?, ?, ?)";
                            $stmt = mysqli_prepare($con, $query_addUser);
                            mysqli_stmt_bind_param($stmt, "sssiss", $username, $password, $address, $area_id, $phone, $email);
                        }
                        break;
                    case 'manufacturer':
                        $man_name = $_POST['man_name'];
                        $man_email = $_POST['man_email'];
                        $man_phone = $_POST['man_phone'];

                        // Validate additional fields for manufacturer
                        if (validate_phone($man_phone) !== true) {
                            $otherErr = validate_phone($man_phone);
                        }
                        if (validate_email($man_email) !== true) {
                            $otherErr = validate_email($man_email);
                        }

                        if (empty($otherErr)) {
                            $query_addUser = "INSERT INTO manufacturer (username, password, man_name, man_email, man_phone) VALUES (?, ?, ?, ?, ?)";
                            $stmt = mysqli_prepare($con, $query_addUser);
                            mysqli_stmt_bind_param($stmt, "sssss", $username, $password, $man_name, $man_email, $man_phone);
                        }
                        break;
                    default:
                        $requireErr = "* Invalid Role Selected";
                }

                if (empty($otherErr) && mysqli_stmt_execute($stmt)) {
                    echo "<script> alert('User added successfully'); </script>";
                    header("Refresh:0");
                } else {
                    $requireErr = "* Adding user failed";
                }
            }
        } else {
            $requireErr = "* All fields are required";
        }
    }
} else {
    header('Location: ../index.php');
    exit();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Add User</title>
    <link rel="stylesheet" href="../includes/main_style.css">
</head>
<body>
    <?php include("../includes/header.inc.php"); ?>
    <?php include("../includes/nav_admin.inc.php"); ?>
    <?php include("../includes/aside_admin.inc.php"); ?>
    <section>
        <h1>Add User</h1>
        <form action="<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>" method="POST" class="form">
            <ul class="form-list">
                <li>
                    <div class="label-block"><label for="newUser">New User</label></div>
                    <div class="input-box"><input type="text" id="newUser" name="txtNewUser" placeholder="New User" required /></div>
                    <span class="error_message"><?php echo $usernameErr; ?></span>
                </li>
                <li>
                    <div class="label-block"><label for="password">Password</label></div>
                    <div class="input-box"><input type="password" id="password" name="txtPassword" placeholder="Password" required /></div>
                    <span class="error_message"><?php echo $passwordErr; ?></span>
                </li>
                <li>
                    <div class="label-block"><label for="confirmPassword">Confirm Password</label></div>
                    <div class="input-box"><input type="password" id="confirmPassword" name="txtConfirmPassword" placeholder="Confirm Password" required /></div>
                    <span class="error_message"><?php echo $matchErr; ?></span>
                </li>
                <li>
                    <div class="label-block"><label for="role">Role</label></div>
                    <div class="input-box">
                        <select name="role" id="role" onchange="showRoleSpecificFields(this.value)" required>
                            <option value="" disabled selected>-- Select Role --</option>
                            <option value="admin">Admin</option>
                            <option value="manufacturer">Manufacturer</option>
                            <option value="retailer">Retailer</option>
                        </select>
                    </div>
                </li>
                <div id="role-specific-fields"></div>
                <li>
                    <input type="submit" value="Add User" class="submit_button" />
                    <span class="error_message"><?php echo $requireErr; ?><?php echo $otherErr; ?></span>
                </li>
            </ul>
        </form>
    </section>
    <?php include("../includes/footer.inc.php"); ?>
    <script>
        function showRoleSpecificFields(role) {
            let roleSpecificFields = document.getElementById('role-specific-fields');
            roleSpecificFields.innerHTML = '';
            if (role === 'retailer') {
                roleSpecificFields.innerHTML = `
                    <li>
                        <div class="label-block"><label for="address">Address</label></div>
                        <div class="input-box"><input type="text" id="address" name="address" placeholder="Address" required /></div>
                    </li>
                    <li>
                        <div class="label-block"><label for="area_id">Area</label></div>
                        <div class="input-box">
                            <select name="area_id" id="area_id" required>
                                <option value="" disabled selected>-- Select Area --</option>
                                <option value="1">Talisay</option>
                                <option value="2">Silay</option>
                                <option value="3">Bacolod</option>
                                <option value="4">E. B. Magalona</option>
                                <option value="5">Victorias</option>
                            </select>
                        </div>
                    </li>
                    <li>
                        <div class="label-block"><label for="phone">Phone</label></div>
                        <div class="input-box"><input type="text" id="phone" name="phone" placeholder="Phone" required /></div>
                    </li>
                    <li>
                        <div class="label-block"><label for="email">Email</label></div>
                        <div class="input-box"><input type="email" id="email" name="email" placeholder="Email" required /></div>
                    </li>`;
            } else if (role === 'manufacturer') {
                roleSpecificFields.innerHTML = `
                    <li>
                        <div class="label-block"><label for="man_name">Manufacturer Name</label></div>
                        <div class="input-box"><input type="text" id="man_name" name="man_name" placeholder="Manufacturer Name" required /></div>
                    </li>
                    <li>
                        <div class="label-block"><label for="man_email">Manufacturer Email</label></div>
                        <div class="input-box"><input type="email" id="man_email" name="man_email" placeholder="Manufacturer Email" required /></div>
                    </li>
                    <li>
                        <div class="label-block"><label for="man_phone">Manufacturer Phone</label></div>
                        <div class="input-box"><input type="text" id="man_phone" name="man_phone" placeholder="Manufacturer Phone" required /></div>
                    </li>`;
            }
        }
    </script>
</body>
</html>

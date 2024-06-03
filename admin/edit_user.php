<?php
include("../includes/config.php");
include("../includes/validate_data.php");
session_start();
if(isset($_SESSION['admin_login'])) {
    $requireErr = $oldPasswordErr = $matchErr = $usernameErr = "";

    if($_SERVER['REQUEST_METHOD'] == "POST") {
        // Check if old password is provided
        if(!empty($_POST['txtOldPassword'])){
            $password = $_POST['txtOldPassword'];
            $query_oldPassword = "SELECT password FROM admin WHERE id=1";
            $result_oldPassword = mysqli_query($con,$query_oldPassword);
            $row_oldPassword = mysqli_fetch_array($result_oldPassword);

            if($row_oldPassword) {
                if(password_verify($password, $row_oldPassword['password'])) {
                    // Validate new password and confirm password
                    if(!empty($_POST['txtNewPassword']) && !empty($_POST['txtConfirmPassword'])){
                        $newPassword = $_POST['txtNewPassword'];
                        $confirmPassword = $_POST['txtConfirmPassword'];

                        if(strcmp($newPassword,$confirmPassword) == 0) {
                            // Hash the new password
                            $hashedPassword = password_hash($newPassword, PASSWORD_DEFAULT);

                            $query_UpdatePassword = "UPDATE admin SET password=? WHERE id=1";
                            $stmt = mysqli_prepare($con, $query_UpdatePassword);
                            mysqli_stmt_bind_param($stmt, "s", $hashedPassword);
                            if(mysqli_stmt_execute($stmt)) {
                                echo "<script>alert('Password Updated Successfully');</script>";
                                header("Refresh:0");
                            } else {
                                $requireErr = "* Updating Password Failed";
                            }
                        } else {
                            $matchErr = "* Passwords do not match";
                        }
                    } else {
                        $requireErr = "* All Fields are required";
                    }

                    // Validate and update username
                    if(!empty($_POST['txtNewUsername'])) {
                        $newUsername = $_POST['txtNewUsername'];
                        $query_UpdateUsername = "UPDATE admin SET username=? WHERE id=1";
                        $stmt = mysqli_prepare($con, $query_UpdateUsername);
                        mysqli_stmt_bind_param($stmt, "s", $newUsername);
                        if(mysqli_stmt_execute($stmt)) {
                            echo "<script>alert('Username Updated Successfully');</script>";
                            header("Refresh:0");
                        } else {
                            $usernameErr = "* Updating Username Failed";
                        }
                    } else {
                        $requireErr = "* All Fields are required";
                    }
                } else {
                    $oldPasswordErr = "* Old Password does not match";
                }
            } else {
                $oldPasswordErr = "* Old Password does not match";
            }
        } else {
            $requireErr = "* All Fields are required";
        }
    }
} else {
    header('Location:../index.php');
    exit();
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>Edit Profile</title>
    <link rel="stylesheet" href="../includes/main_style.css">
</head>
<body>
    <?php
    include("../includes/header.inc.php");
    include("../includes/nav_admin.inc.php");
    include("../includes/aside_admin.inc.php");
    ?>
    <section>
        <h1>Edit Profile</h1>
        <form action="" method="POST" class="form">
            <ul class="form-list">
                <li>
                    <div class="label-block"><label for="oldPassword">Old Password</label></div>
                    <div class="input-box"><input type="password" id="oldPassword" name="txtOldPassword" placeholder="Old Password" required /></div>
                    <span class="error_message"><?php echo $oldPasswordErr; ?></span>
                </li>
                <li>
                    <div class="label-block"><label for="newUsername">New Username</label></div>
                    <div class="input-box"><input type="text" id="newUsername" name="txtNewUsername" placeholder="New Username" required /></div>
                    <span class="error_message"><?php echo $usernameErr; ?></span>
                </li>
                <li>
                    <div class="label-block"><label for="newPassword">New Password</label></div>
                    <div class="input-box"><input type="password" id="newPassword" name="txtNewPassword" placeholder="New Password" required /></div>
                </li>
                <li>
                    <div class="label-block"><label for="confirmPassword">Confirm Password</label></div>
                    <div class="input-box"><input type="password" id="confirmPassword" name="txtConfirmPassword" placeholder="Confirm Password" required /></div>
                    <span class="error_message"><?php echo $matchErr; ?></span>
                </li>
                <li>
                    <input type="submit" value="Change Password" class="submit_button" />
                    <span class="error_message"><?php echo $requireErr; ?></span>
                </li>
            </ul>
        </form>
    </section>
    <?php
    include("../includes/footer.inc.php");
    ?>
</body>
</html>

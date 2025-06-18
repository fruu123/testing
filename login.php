<?php
header('Content-Type: application/json');

// Enable error reporting for debugging, but disable display to prevent HTML error messages
error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', 'php-error.log');

// Start output buffering to prevent any unexpected output from breaking JSON response
ob_start();

// Function to send JSON response
function sendResponse($status, $message, $data = []) {
    ob_clean(); // Clear any previous output
    echo json_encode([
        'status'  => $status,
        'message' => $message,
        'data'    => $data
    ]);
    exit;
}

// Helper function to generate a secure token
function generateToken($userId) {
    return hash('sha256', $userId . uniqid() . time());
}

try {
    if (!isset($_REQUEST['email']) || !isset($_REQUEST['pass'])) {
        sendResponse("error", "Email and password are required.");
    }

    $email = stripslashes($_REQUEST['email']);
    $pass  = stripslashes($_REQUEST['pass']);

    if (trim($pass) == "" || filter_var(trim($email), FILTER_VALIDATE_EMAIL) === false) {
        sendResponse("error", "Invalid email or password.");
    }

    $dbConfig = brilliantDirectories::getDatabaseConfiguration('database');

    $val = mysql($dbConfig, 'SELECT 1 FROM password_retrieval_sessions LIMIT 1');
    $passwordVar = $val !== FALSE ? brilliantDirectories::encryptPassword(trim($pass)) : trim($pass);

    $lresults = mysql($dbConfig, "SELECT * FROM users_data WHERE email='" . mysql_real_escape_string(trim($email)) . "' AND password='" . mysql_real_escape_string($passwordVar) . "' ORDER BY user_id DESC LIMIT 1");

    if (!$lresults) {
        sendResponse("error", "Database query failed: " . mysql_error());
    }

    $user = mysql_fetch_assoc($lresults);

    if ($user) {
        $token = generateToken($user['user_id']);
        $expiryDate = date('Y-m-d H:i:s', strtotime('+7 days'));
        $storeTokenQuery = "INSERT INTO user_tokens (user_id, token, expires_at) VALUES ('" . $user['user_id'] . "', '" . mysql_real_escape_string($token) . "', '$expiryDate') 
                            ON DUPLICATE KEY UPDATE token = '$token', expires_at = '$expiryDate'";

        if (!mysql($dbConfig, $storeTokenQuery)) {
            sendResponse("error", "Failed to generate login token.");
        }

        mysql($dbConfig, "UPDATE users_data SET last_login = '" . date('Y-m-d H:i:s') . "' WHERE user_id = '" . $user['user_id'] . "'");
        logUserActivity($user['user_id'], "Log In", $w);

        $ip = $_SERVER['HTTP_CLIENT_IP'] ?? ($_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR']);
        $lastLoginIP = ['last_login_ip' => $ip];
        storeMetaData("users_data", $user['user_id'], $lastLoginIP, $w);

        $user['full_name'] = trim($user['first_name'] . ' ' . $user['last_name']);
        $pic = getUserPhoto($user['user_id'], $user['listing_type'], $w);
        $user['user_photo'] = 'http://' . $w['website_url'] . $pic['file'];

        // Fetch subscription name
        $subscriptionQuery = "SELECT subscription_name FROM subscription_types WHERE subscription_id = '" . mysql_real_escape_string($user['subscription_id']) . "' LIMIT 1";
        $subscriptionResult = mysql($dbConfig, $subscriptionQuery);

        if ($subscriptionResult) {
            $subscriptionData = mysql_fetch_assoc($subscriptionResult);
            $user['subscription_name'] = $subscriptionData['subscription_name'] ?? "Unknown Plan";
        } else {
            $user['subscription_name'] = "Unknown Plan";
        }

        // Check if active_status should be set to 1
        $activeStatus = 0; // Default active status
        if (!in_array($user['subscription_id'], [19, 18, 9, 5, 4, 3]) && $user['active'] == 2) {
            $activeStatus = 1; // Set to 1 if conditions are met
        }

        // Add search_description from users_data as short_bio
        $shortBio = isset($user['search_description']) ? $user['search_description'] : '';

        $json = [
            'result'            => "success",
            'message'           => "Login successful",
            'user_id'           => $user['user_id'],
            'token'             => $user['token'],
            'expires_at'        => $expiryDate,
            'full_name'         => $user['full_name'],
            'user_photo'        => $user['user_photo'],
            'active'            => $user['active'],
            'subscription_name' => $user['subscription_name'],
            'active_status'     => $activeStatus,
            'short_bio'         => $shortBio
        ];

        sendResponse("success", "Login successful", $json);
    } else {
        sendResponse("error", "Invalid email or password");
    }
} catch (Exception $e) {
    sendResponse("error", "An unexpected error occurred: " . $e->getMessage());
}

ob_end_flush();
?>

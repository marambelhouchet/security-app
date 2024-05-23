<?php
// Database connection parameters
$servername = "127.0.0.4";
$username = "root";
$password = "root";
$dbname = "contact";

// Check if the correct number of arguments are provided
if ($argc != 4) {
    die("Usage: php database.php <name> <email> <message>\n");
}

// Extract command-line arguments
$name = $argv[1];
$email = $argv[2];
$message = $argv[3];

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Insert data into database
$sql = "INSERT INTO contacts (name, email, message) VALUES ('$name', '$email', '$message')";
if ($conn->query($sql) === TRUE) {
    echo "New record created successfully";
} else {
    echo "Error: " . $sql . "<br>" . $conn->error;
}

$conn->close();



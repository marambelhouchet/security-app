import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import pkg from 'pg';
import bodyParser from 'body-parser';
import jwt from 'jsonwebtoken';

dotenv.config(); // Load environment variables from .env file

const { Client } = pkg; // Destructure Client from the imported package

const app = express();

// Middleware to handle CORS
app.use(
  cors({
    origin: process.env.FRONTEND_URL || "https://taskmanager-production-0f39.up.railway.app", // Frontend URL for local dev
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type'],
  })
);

app.use(express.json()); // For parsing application/json
app.use(bodyParser.json()); // Extra body parser for redundancy

// PostgreSQL connection
const client = new Client({
  connectionString: process.env.DATABASE_URL || "postgresql://postgres:gQdJjYWauEpyyzHogbUCqosNxgmMvLcR@autorack.proxy.rlwy.net:55202/railway", // Fallback for local DB
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
});

client.connect()
  .then(() => console.log('Connected to PostgreSQL database'))
  .catch((err) => console.error('Error connecting to the database:', err));

// Helper function for error logging
const logError = (message, error) => {
  console.error(`${message}:`, error);
};


// Signin route
app.post("/signin", async (req, res) => {
  try {
    const { email, password } = req.body;

    console.log("Received signin data:", { email, password });

    // Check if user exists
    const checkUserQuery = "SELECT * FROM users WHERE email = $1";
    const existingUser = await client.query(checkUserQuery, [email]);

    if (existingUser.rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    const user = existingUser.rows[0];

    // Validate password (plain text comparison)
    if (password !== user.password) {
      return res.status(401).json({ message: "Invalid password" });
    }

    // Get the current timestamp
    const loginTime = new Date();

    // Update or insert into the user_activity table
    const activityQuery = `
      INSERT INTO user_activity (user_id, login_time, login_count)
      VALUES ($1, $2, 1)
      ON CONFLICT (user_id)
      DO UPDATE SET
        login_time = $2,
        login_count = user_activity.login_count + 1
      RETURNING *;
    `;

    const activityResult = await client.query(activityQuery, [user.id, loginTime]);
    const activityData = activityResult.rows[0];

    // Respond with user data and activity data
    res.status(200).json({
      message: "Signin successful",
      user: { id: user.id, name: user.name, email: user.email },
      activity: activityData,
    });

  } catch (error) {
    console.error("Error signing in:", error);

    res.status(500).json({
      message: "Error signing in",
      error: error.message || "Unknown error",
    });
  }
});

// Server setup
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
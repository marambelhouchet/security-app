import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import pkg from 'pg';
import bodyParser from 'body-parser';

dotenv.config(); // Load environment variables from .env file

const { Client } = pkg;

const app = express();

// Middleware to handle CORS
app.use(
  cors({
    origin: process.env.FRONTEND_URL || "http://localhost:3001", // Frontend URL for local dev
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

client
  .connect()
  .then(() => console.log('Connected to PostgreSQL database'))
  .catch((err) => console.error('Error connecting to the database:', err));

// Consolidated stats endpoint
app.get('/stats', async (req, res) => {
  try {
    // Query 1: Project activity stats
    const projectActivityQuery = `
      SELECT 
        user_id, 
        project_id, 
        COUNT(*) AS activity_count, 
        MIN(created_at) AS first_activity, 
        MAX(created_at) AS last_activity
      FROM project_activity
      GROUP BY user_id, project_id
      ORDER BY user_id, project_id;
    `;
    const projectActivityResult = await client.query(projectActivityQuery);

    // Query 2: User activity stats
    const userActivityQuery = `
      SELECT 
        user_id, 
        login_count, 
        projects_per_day, 
        active_days, 
        project_count, 
        days_active
      FROM user_activity
      ORDER BY user_id;
    `;
    const userActivityResult = await client.query(userActivityQuery);

    // Query 3: Summary stats
    const summaryStatsQuery = `
      SELECT 
        COUNT(DISTINCT user_id) AS total_users, 
        COUNT(DISTINCT project_id) AS total_projects, 
        SUM(login_count) AS total_logins, 
        AVG(projects_per_day) AS avg_projects_per_day 
      FROM user_activity;
    `;
    const summaryStatsResult = await client.query(summaryStatsQuery);

    // Ensure numeric values (convert any string values to numbers)
    const response = {
      projectActivity: projectActivityResult.rows,
      userActivity: userActivityResult.rows.map((row) => ({
        ...row,
        active_days: Number(row.active_days), // Convert to number
        login_count: Number(row.login_count), // Convert to number
        projects_per_day: parseFloat(row.projects_per_day), // Convert to number
        project_count: Number(row.project_count), // Convert to number
        days_active: Number(row.days_active), // Convert to number
      })),
      summaryStats: {
        ...summaryStatsResult.rows[0],
        total_users: Number(summaryStatsResult.rows[0].total_users),
        total_projects: Number(summaryStatsResult.rows[0].total_projects),
        total_logins: Number(summaryStatsResult.rows[0].total_logins),
        avg_projects_per_day: parseFloat(summaryStatsResult.rows[0].avg_projects_per_day),
      },
    };

    res.json(response);
  } catch (err) {
    console.error('Error fetching stats:', err);
    res.status(500).send('Error fetching stats');
  }
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

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

client
  .connect()
  .then(() => console.log('Connected to PostgreSQL database'))
  .catch((err) => console.error('Error connecting to the database:', err));
  app.get('/stats', async (req, res) => {
    try {
      // Query to get project counts grouped by day of the week
      const projectsPerDayQuery = `
        SELECT 
          TRIM(TO_CHAR(created_at, 'Day')) AS day_of_week, -- Trim spaces from day names
          COUNT(*) AS project_count
        FROM project_activity
        GROUP BY TRIM(TO_CHAR(created_at, 'Day')), TO_CHAR(created_at, 'D')
        ORDER BY 
          CASE 
            WHEN TO_CHAR(created_at, 'D') = '1' THEN 7 -- Sunday as last
            ELSE TO_CHAR(created_at, 'D')::int - 1
          END;
      `;
      const result = await client.query(projectsPerDayQuery);
  
      // Response
      const response = result.rows.map((row) => ({
        day: row.day_of_week,
        project_count: Number(row.project_count),
      }));
  
      res.json(response);
    } catch (err) {
      console.error('Error fetching projects per day:', err);
      res.status(500).send('Error fetching projects per day');
    }
  });
  

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
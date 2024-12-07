const express = require('express');
const { Client } = require('pg');
require('dotenv').config();

const app = express();
const router = express.Router();
app.use(express.json());

// Set up PostgreSQL client
const client = new Client({
  connectionString: process.env.DATABASE_URL,
});
client.connect(); // Connect to the database


// Create project route
app.post('/api/projects', async (req, res) => {
  try {
    const { userId, projectName, projectDescription, deadline, status } = req.body;

    if (!userId || !projectName || !projectDescription || !deadline) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    const result = await client.query(
      'INSERT INTO projects (name, description, deadline, status, user_id) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [projectName, projectDescription, deadline, status, userId]
    );

    const createdProject = result.rows[0];
    console.log('Project created:', createdProject);

    // Log project activity in the project_activity table
    const logProjectActivityQuery = `
      INSERT INTO project_activity (user_id, project_id, created_at) 
      VALUES ($1, $2, $3) RETURNING *`;
    await client.query(logProjectActivityQuery, [userId, createdProject.id, new Date()]);

    // Send back the full project details
    res.status(201).json({ project: createdProject });
  } catch (error) {
    console.error('Error creating project:', error);
    res.status(500).json({ message: 'Error creating project', error });
  }
});
// Fetch all projects
app.get('/api/projects', async (req, res) => {
  try {
    const { userId } = req.query;
    console.log('Received userId from query:', userId);  // Log the received userId for debugging

    if (!userId) {
      console.log('Fetch projects failed: Missing userId');
      return res.status(400).json({ message: 'User ID is required' });
    }

    const result = await client.query(`
      SELECT 
        p.id AS project_id,
        p.name AS project_name,
        p.description AS project_description,
        p.deadline AS deadline,
        p.status AS status,
        t.id AS task_id,
        t.name AS task_name,
        t.description AS task_description,
        t.due_time AS due_time,
        t.assigned_user AS assigned_user
      FROM projects p
      LEFT JOIN project_activity pa ON p.id = pa.project_id
      LEFT JOIN tasks t ON p.id = t.project_id
      WHERE p.user_id = $1
    `, [userId]);

    console.log('Database query result:', result.rows);

    if (result.rows.length === 0) {
      console.log('No projects found for user:', userId);
      return res.status(404).json({ message: 'No projects found for this user' });
    }

    const projects = [];
    let currentProject = null;

    result.rows.forEach(row => {
      if (!currentProject || currentProject.id !== row.project_id) {
        if (currentProject) {
          projects.push(currentProject); // Push the completed project
        }
        currentProject = {
          id: row.project_id,
          name: row.project_name,
          description: row.project_description,
          deadline: row.deadline,
          status: row.status,
          tasks: []  // Initialize tasks array for each new project
        };
      }
      if (row.task_id) {
        console.log(`Adding task to project: ${row.project_name}, task: ${row.task_name}`);
        currentProject.tasks.push({
          id: row.task_id,
          name: row.task_name,
          description: row.task_description,
          due_time: row.due_time,
          assigned_user: row.assigned_user
        });
      }
    });


    res.status(200).json({ projects });
  } catch (error) {
    console.error('Error fetching projects:', error);
    res.status(500).json({ message: 'Error fetching projects', error: error.message });
  }
});


// Set up your server and routes
app.use(router);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

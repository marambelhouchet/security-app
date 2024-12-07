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

// Routes

// User Signup Route
app.post('/api/signup', async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  try {
    // Check if user already exists
    const checkUserQuery = 'SELECT * FROM users WHERE email = $1';
    const existingUser = await client.query(checkUserQuery, [email]);

    if (existingUser.rows.length > 0) {
      return res.status(409).json({ message: 'User already exists' });
    }

    // Insert the user into the database
    const insertQuery = 'INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id, name, email';
    const result = await client.query(insertQuery, [name, email, password]); // Use hashed password in production!
    const user = result.rows[0];

    res.status(201).json({ message: 'Signup successful', user });
  } catch (error) {
    logError('Signup error', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Route for fetching user data
app.get('/api/users', async (req, res) => {
  try {
    const { userId } = req.query;
    if (!userId) {
      return res.status(400).json({ message: 'User ID is required' });
    }

    const result = await client.query('SELECT id, name, email FROM users WHERE id = $1', [userId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.status(200).json({ user: result.rows[0] });
  } catch (error) {
    console.error('Error fetching user data:', error);
    res.status(500).json({ message: 'Error fetching user data', error: error.message });
  }
});

// Route for updating user data
app.put('/api/users', async (req, res) => {
  try {
    const { userId, name, email, password } = req.body;

    if (!userId || (!name && !email && !password)) {
      return res.status(400).json({ message: 'User ID and at least one field (name, email, or password) are required' });
    }

    const updateFields = [];
    const values = [];
    let i = 1;

    if (name) {
      updateFields.push(`name = $${i++}`);
      values.push(name);
    }

    if (email) {
      updateFields.push(`email = $${i++}`);
      values.push(email);
    }

    if (password) {
      updateFields.push(`password = $${i++}`);
      values.push(password);
    }

    values.push(userId);

    const queryText = `UPDATE users SET ${updateFields.join(", ")} WHERE id = $${i} RETURNING id, name, email`;

    const result = await client.query(queryText, values);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    const updatedUser = result.rows[0];
    res.status(200).json({ user: updatedUser });
  } catch (error) {
    console.error('Error updating user data:', error);
    res.status(500).json({ message: 'Error updating user data', error: error.message });
  }
});
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


app.post('/api/tasks', async (req, res) => {
  try {
    const { name, description, assigned_user, due_time, project_id, user_id } = req.body;

    console.log('Create task request received:', req.body); // Log the incoming task data

    // Check if required fields are provided
    if (!name || !description || !project_id || !due_time || !user_id) {
      console.log('Create task failed: Missing fields');
      return res.status(400).json({ message: 'Task name, description, project ID, due time, and user ID are required' });
    }

    // Check if the project exists
    const projectResult = await client.query('SELECT * FROM projects WHERE id = $1', [project_id]);

    if (projectResult.rows.length === 0) {
      console.log('Create task failed: Project not found');
      return res.status(404).json({ message: 'Project not found' });
    }

    // Insert the new task into the database, including user_id
    const result = await client.query(
      'INSERT INTO tasks (name, description, project_id, due_time, assigned_user, user_id) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
      [name, description, project_id, due_time, assigned_user || null, user_id] // Use null for assigned_user if not provided
    );

    // Log all the task details that were inserted into the database
    console.log('Task created successfully:', result.rows[0]);

    // Send back the full task details
    res.status(201).json({
      message: 'Task created successfully',
      task: result.rows[0],  // Return the task object that was created
    });
  } catch (error) {
    console.error('Error creating task:', error);
    res.status(500).json({ message: 'Error creating task', error: error.message });
  }
});

// Delete projects by user_id
app.delete('/api/delprojects', async (req, res) => {
  const { userId, projectId } = req.body;

  // Check if userId and projectId are provided
  if (!userId || !projectId) {
    return res.status(400).json({ message: 'Missing userId or projectId' });
  }

  try {
    // Check if the project exists for the given userId
    const result = await client.query(
      'SELECT * FROM projects WHERE user_id = $1 AND id = $2',
      [userId, projectId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Project not found' });
    }

    // If project exists, first delete related tasks
    await client.query(
      'DELETE FROM tasks WHERE project_id = $1',
      [projectId]
    );

    // Then delete the project from the projects table
    await client.query(
      'DELETE FROM projects WHERE id = $1 AND user_id = $2',
      [projectId, userId]
    );

    // Return a success message
    res.status(200).json({ message: 'Project deleted successfully' });
  } catch (error) {
    console.error('Error deleting project:', error);
    res.status(500).json({ message: 'Error deleting project', error });
  }
});
app.delete('/api/deltasks', async (req, res) => {
  const { userId, taskId } = req.body;

  // Log the incoming request data for debugging
  console.log('Received DELETE request to /api/deltasks');
  console.log('Request Body:', req.body);

  if (!userId || !taskId) {
    console.log('Error: Missing userId or taskId');
    return res.status(400).json({ message: 'Missing parameters' });
  }

  try {
    // Log before querying the database
    console.log(`Attempting to delete task with ID: ${taskId} for user with ID: ${userId}`);

    // Example query to delete task by taskId and userId
    const result = await client.query(
      'DELETE FROM tasks WHERE id = $1 AND user_id = $2',
      [taskId, userId]
    );

    // Log query result
    console.log('Database Query Result:', result);

    if (result.rowCount === 0) {
      console.log(`No task found with ID: ${taskId} for user ID: ${userId}`);
      return res.status(404).json({ message: 'Task not found or not authorized' });
    }

    // Log successful deletion
    console.log(`Task with ID: ${taskId} deleted successfully for user ID: ${userId}`);
    res.status(200).json({ message: 'Task deleted successfully' });
  } catch (error) {
    // Log error if something goes wrong
    console.error('Error deleting task:', error);
    res.status(500).json({ message: 'Error deleting task', error });
  }
});

app.get('/api/projects', async (req, res) => {
  try {
    const { userId } = req.query;
    console.log('Received userId from query:', userId);  // Log the received userId for debugging

    if (!userId) {
      console.log('Fetch projects failed: Missing userId');
      return res.status(400).json({ message: 'User ID is required' });
    }

    // Query the projects table to get all projects belonging to the user, and join with the tasks table
    const result = await client.query(`
      SELECT p.id AS project_id, p.name AS project_name, p.description AS project_description, p.deadline, p.status, 
             t.id AS task_id, t.name AS task_name, t.description AS task_description, t.due_time, t.assigned_user
      FROM projects p
      LEFT JOIN tasks t ON p.id = t.project_id
      WHERE p.user_id = $1
      ORDER BY p.id, t.due_time;
    `, [userId]);

    console.log('Database query result:', result.rows);  // Log the query result for debugging

    if (result.rows.length === 0) {
      console.log('No projects found for user:', userId);
      return res.status(404).json({ message: 'No projects found for this user' });
    }

    // Format the result to group tasks under their respective projects
    const projects = [];
    let currentProject = null;

    result.rows.forEach(row => {
      // Check if we are starting a new project
      if (!currentProject || currentProject.project_id !== row.project_id) {
        // If so, push the previous project (if any) to the projects array
        if (currentProject) {
          projects.push(currentProject);
        }

        // Start a new project
        currentProject = {
          id: row.project_id,
          name: row.project_name,
          description: row.project_description,
          deadline: row.deadline,
          status: row.status,
          tasks: []  // Initialize tasks as an empty array
        };
      }

      // Add the task to the current project if it exists
      if (row.task_id) {
        console.log(`Adding task to project: ${row.project_name}, task: ${row.task_name}`);  // Log the task being added
        currentProject.tasks.push({
          id: row.task_id,
          name: row.task_name,
          description: row.task_description,
          due_time: row.due_time,
          assigned_user: row.assigned_user
        });
      }
    });

    // Push the last project to the projects array
    if (currentProject) {
      console.log('Adding last project:', currentProject.name);  // Log the final project
      projects.push(currentProject);
    }

    console.log('Grouped projects with tasks:', projects);  // Log the final projects array with tasks

    res.status(200).json({ projects });
  } catch (error) {
    console.error('Error fetching projects:', error);
    res.status(500).json({ message: 'Error fetching projects', error: error.message });
  }
});

// Server setup
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});

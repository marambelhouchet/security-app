const express = require('express');
const { Client } = require('pg');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors()); // Enable CORS for cross-origin requests

// Set up PostgreSQL client
const client = new Client({
  connectionString: process.env.DATABASE_URL, // Replace with your actual database URL or credentials
});

client.connect(); // Connect to the PostgreSQL database

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

// Set up your server and routes
app.use(router);
// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

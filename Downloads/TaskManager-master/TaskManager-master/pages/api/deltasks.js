const express = require('express');
const { Client } = require('pg');
require('dotenv').config();

const app = express();
const router = express.Router();
app.use(express.json());

// Set up PostgreSQL client
const client = new Client({
  connectionString: process.env.DATABASE_URL, // URL of your database, or configure host, user, password, etc.
});

client.connect(); // Ensure to connect to the database
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


// Set up your server and routes
app.use(router);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

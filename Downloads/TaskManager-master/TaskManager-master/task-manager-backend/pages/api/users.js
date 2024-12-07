import express from 'express';
import { Client } from 'pg';
import dotenv from 'dotenv';
import cors from 'cors';

dotenv.config();

const app = express();

// Enable CORS for all routes
app.use(cors());

app.use(express.json());

// Set up PostgreSQL client
const client = new Client({
  connectionString: process.env.DATABASE_URL,
});

client.connect();

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
    console.log('Received request to update user data:', req.body);

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

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

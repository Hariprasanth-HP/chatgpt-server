require('dotenv').config();
const { Pool } = require('pg');

 const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  }
});

// Function to create a table
const createTable = async () => {
  try {
    const client = await pool.connect();
    console.log('Connected to the PostgreSQL database.');

    // Define the SQL query to create a table
    // const createTableQuery = `
    //   DROP TABLE IF EXISTS users;
    // `;
    const createTableQuery = `
      CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password TEXT NOT NULL,
    refresh_token TEXT
);

    `;

    // Execute the query
    await client.query(createTableQuery);
    console.log('Table "users" created successfully.');

    client.release();
  } catch (err) {
    console.error('Error creating table:', err);
  }
};

// Run the create table function
createTable();
module.exports = pool;


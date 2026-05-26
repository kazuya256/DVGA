const { Client } = require('pg');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

const dbConfig = {
  user: process.env.DB_USER || 'postgres',
  host: process.env.DB_HOST || 'localhost',
  password: process.env.DB_PASSWORD || 'postgres',
  port: parseInt(process.env.DB_PORT || '5432', 10),
};

const dbName = process.env.DB_NAME || 'dvga_node';

async function initDatabase() {
  console.log('=========================================================================');
  console.log('DVGA-NODE DATABASE INITIALIZER');
  console.log('=========================================================================');

  // Connect to postgres default database first to create the target database if not exists
  const client = new Client({ ...dbConfig, database: 'postgres' });
  
  try {
    await client.connect();
    
    // Check if database exists
    const res = await client.query('SELECT 1 FROM pg_database WHERE datname = $1', [dbName]);
    if (res.rowCount === 0) {
      console.log(`Database "${dbName}" does not exist. Creating...`);
      // CREATE DATABASE cannot run in a transaction block, execute directly
      await client.query(`CREATE DATABASE ${dbName}`);
      console.log(`Database "${dbName}" created successfully.`);
    } else {
      console.log(`Database "${dbName}" already exists.`);
    }
  } catch (err) {
    console.error('Failed to create/verify target database:', err.message);
    throw err;
  } finally {
    await client.end();
  }

  // Now connect to the actual target database to build tables and seed data
  const dbClient = new Client({ ...dbConfig, database: dbName });
  
  try {
    await dbClient.connect();
    
    console.log('Applying schema database definitions from schema.sql...');
    const schemaSql = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8');
    await dbClient.query(schemaSql);
    console.log('Schema setup completed.');

    // Let's seed users with hashed passwords using bcrypt to make it realistic
    console.log('Seeding training accounts...');
    
    const users = [
      { email: 'admin@lab.local', password: 'Admin123!', role: 'admin', is_admin: true, name: 'System Administrator' },
      { email: 'user_a@lab.local', password: 'User123!', role: 'user', is_admin: false, name: 'Alice Smith' },
      { email: 'user_b@lab.local', password: 'User123!', role: 'user', is_admin: false, name: 'Bob Johnson' }
    ];

    for (const u of users) {
      const hash = await bcrypt.hash(u.password, 10);
      const userRes = await dbClient.query(
        'INSERT INTO users (email, password_hash, role, is_admin) VALUES ($1, $2, $3, $4) RETURNING id',
        [u.email, hash, u.role, u.is_admin]
      );
      const userId = userRes.rows[0].id;
      
      // Create profile record matching users
      await dbClient.query(
        'INSERT INTO profiles (user_id, full_name, bio, phone, address) VALUES ($1, $2, $3, $4, $5)',
        [
          userId, 
          u.name, 
          `Hi, I am ${u.name}. Welcome to the learning lab!`, 
          u.role === 'admin' ? '+1-555-0199' : '+1-555-0102',
          u.role === 'admin' ? '123 Admin Rd, SecureCity' : `User Route Suite ${userId}`
        ]
      );
    }

    console.log('Inserting default seed data...');
    const seedSql = fs.readFileSync(path.join(__dirname, 'seed.sql'), 'utf8');
    await dbClient.query(seedSql);

    // Seed some orders associated with alice & bob
    console.log('Seeding orders metadata...');
    await dbClient.query(
      'INSERT INTO orders (user_id, product_id, quantity, tracking_number) VALUES ($1, $2, $3, $4)',
      [2, 1, 1, 'TRK-ALICE-8819']
    );
    await dbClient.query(
      'INSERT INTO orders (user_id, product_id, quantity, tracking_number) VALUES ($1, $2, $3, $4)',
      [3, 2, 2, 'TRK-BOB-9923']
    );

    console.log('Database setup complete. Safe training accounts seeded successfully.');
    console.log('Credentials:\n  - admin@lab.local / Admin123!\n  - user_a@lab.local / User123!\n  - user_b@lab.local / User123!');
    console.log('=========================================================================');
  } catch (err) {
    console.error('Error seeding data/applying schema:', err.stack);
    throw err;
  } finally {
    await dbClient.end();
  }
}

// Automatically execute if run directly
if (require.main === module) {
  initDatabase().catch((err) => {
    process.exit(1);
  });
}

module.exports = initDatabase;

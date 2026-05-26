const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  user: process.env.DB_USER ,
  host: process.env.DB_HOST ,
  database: process.env.DB_NAME ,
  password: process.env.DB_PASSWORD ,
  port: parseInt(process.env.DB_PORT , 10),
});

pool.on('error', (err) => {
  console.error('Unexpected error on idle pg client', err);
});

module.exports = {
  pool,
  /**
   * Secure parameterized query helper
   */
  query: (text, params) => pool.query(text, params),
  
  /**
   * Unsafe raw SQL string execution helper for SQLi challenges
   */
  unsafeQuery: (text) => pool.query(text)
};

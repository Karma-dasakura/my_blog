const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '../.env') });

const bcrypt = require('bcrypt');
const { pool } = require('../src/db');
const { encrypt, emailLookup } = require('../src/crypto');
const { email, password, text } = require('../src/validate');

async function main() {
  const [nameArg, emailArg, passwordArg] = process.argv.slice(2);
  if (!nameArg || !emailArg || !passwordArg) {
    throw new Error('Usage: node scripts/create-admin.js "Admin Name" admin@example.com "StrongPassword"');
  }
  
  const name = text(nameArg, 'Name', { min: 2, max: 80 });
  const cleanEmail = email(emailArg);
  const cleanPassword = password(passwordArg);
  
  const result = await pool.query(
    `INSERT INTO users (display_name, email_lookup, email_encrypted, password_hash, role)
     VALUES ($1, $2, $3, $4, 'admin')
     ON CONFLICT (email_lookup) DO UPDATE SET
       display_name = EXCLUDED.display_name,
       password_hash = EXCLUDED.password_hash,
       role = 'admin'
     RETURNING id, display_name, role`,
    [name, emailLookup(cleanEmail), encrypt(cleanEmail), await bcrypt.hash(cleanPassword, 12)],
  );
  
  console.log(`Admin account is ready (id: ${result.rows[0].id}, role: ${result.rows[0].role}).`);
}

main()
  .catch((error) => { 
    console.error(`Admin setup failed: ${error.message}`); 
    process.exitCode = 1; 
  })
  .finally(() => pool.end());
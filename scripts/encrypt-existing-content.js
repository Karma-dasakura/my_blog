require('dotenv').config();
const { pool } = require('../src/db');
const { encrypt } = require('../src/crypto');
async function encryptTable(client, table) { const column = table === 'posts' ? 'content' : 'body'; const rows = await client.query(`SELECT id, ${column} FROM ${table} WHERE ${column} NOT LIKE 'v1:%' FOR UPDATE`); for (const row of rows.rows) await client.query(`UPDATE ${table} SET ${column}=$1 WHERE id=$2`, [encrypt(row[column]), row.id]); return rows.rowCount; }
async function main() { const client = await pool.connect(); try { await client.query('BEGIN'); const posts = await encryptTable(client, 'posts'); const comments = await encryptTable(client, 'comments'); await client.query('COMMIT'); console.log(`Encrypted ${posts} existing posts and ${comments} existing comments.`); } catch (error) { await client.query('ROLLBACK'); throw error; } finally { client.release(); } }
main().catch((error) => { console.error(`Encryption migration failed: ${error.message}`); process.exitCode = 1; }).finally(() => pool.end());

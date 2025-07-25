import { pool } from '../db.js';
import bcrypt from 'bcryptjs';
import { v4 as uuid } from 'uuid';

const SALT_ROUNDS = +process.env.BCRYPT_SALT_ROUNDS || 12;

export async function createAuthUser({ name, email, password }) {
    const password_hash = await bcrypt.hash(password, SALT_ROUNDS);
    const user_id = uuid();
    const { rows } = await pool.query(
        `INSERT INTO auth_users(user_id, name, email, password_hash)
     VALUES ($1,$2,$3,$4)
     RETURNING user_id, name, email`,
        [user_id, name, email, password_hash]
    );
    return rows[0];
}
export async function deleteUser(user_id) {
    // Execute the DELETE query using the user_id
    const { rowCount } = await pool.query(
        'DELETE FROM auth_users WHERE user_id = $1',
        [user_id]
    );

    // The 'rowCount' property from the query result gives us the number of deleted rows.
    // If rowCount is greater than 0, it means the deletion was successful.
    return rowCount > 0;
}

export async function findByEmail(email) {
    const { rows } = await pool.query(
        `SELECT * FROM auth_users WHERE email=$1`,
        [email]
    );
    return rows[0];
}
export async function findById(id) {
    const { rows } = await pool.query(
        `SELECT * FROM auth_users WHERE user_id=$1`,
        [id]
    );
    return rows[0];
}

export async function saveRefreshToken(user_id, token) {
    await pool.query(
        `UPDATE auth_users SET refresh_token=$2, refresh_token_expires=NOW()+INTERVAL '14 days'
     WHERE user_id=$1`,
        [user_id, token]
    );
}

export async function invalidateRefreshToken(token) {
    await pool.query(
        `UPDATE auth_users SET refresh_token=NULL, refresh_token_expires=NULL
     WHERE refresh_token=$1`,
        [token]
    );
}



//passwort reset via e-mail
export async function saveResetToken(user_id, tokenHash, ttlMin) {
    await pool.query(
        `UPDATE auth_users
       SET reset_token_hash=$2,
           reset_token_expires=NOW() + ($3 || ' minutes')::interval
     WHERE user_id=$1`,
        [user_id, tokenHash, ttlMin]
    );
}



//TODO gluecode not here but somewhere
export async function findByResetToken(tokenHash) {
    const { rows } = await pool.query(
        `SELECT * FROM auth_users
      WHERE reset_token_hash=$1
        AND reset_token_expires > NOW()`,
        [tokenHash]
    );
    return rows[0];
}
//TODO gluecode not here but somewhere
export async function clearResetToken(user_id) {
    await pool.query(
        `UPDATE auth_users
       SET reset_token_hash=NULL,
           reset_token_expires=NULL
     WHERE user_id=$1`,
        [user_id]
    );
}


export async function updatePassword(user_id, rawPw) {
    // 1) hash
    const passwordHash = await bcrypt.hash(rawPw, SALT_ROUNDS);

    // 2) update DB
    await pool.query(
        `UPDATE auth_users
       SET password_hash        = $2,
           refresh_token        = NULL,   -- log all devices out
           reset_token_hash     = NULL,
           reset_token_expires  = NULL
     WHERE user_id = $1`,
        [user_id, passwordHash]
    );
}

export async function updateUserRole(user_id, newRole) {
    const { rowCount } = await pool.query(
        `UPDATE auth_users 
         SET role = $2 
         WHERE user_id = $1`,
        [user_id, newRole]
    );
    return rowCount > 0;
}
export async function updateUserProfile(user_id, { name, email }) {
    // Start with base query
    let query = 'UPDATE auth_users SET ';
    const params = [user_id];
    const updates = [];

    let paramIndex = 2; // Start after user_id

    if (name !== undefined) {
        updates.push(`name = $${paramIndex}`);
        params.push(name);
        paramIndex++;
    }

    if (email !== undefined) {
        updates.push(`email = $${paramIndex}`);
        params.push(email);
        paramIndex++;
    }

    // If no valid updates were provided
    if (updates.length === 0) {
        return false;
    }

    query += updates.join(', ') + ' WHERE user_id = $1';

    const { rowCount } = await pool.query(query, params);
    return rowCount > 0;
}
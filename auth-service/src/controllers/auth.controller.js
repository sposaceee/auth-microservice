import { validationResult } from 'express-validator';
import * as Model from '../models/auth.model.js';
import * as JWT from '../utils/jwt.js';
import bcrypt from 'bcryptjs';
import { generateToken, sendResetMail } from '../utils/password-reset.js';
import crypto from 'crypto';

import 'dotenv/config';
const jwtSecret = process.env.JWT_SECRET;

function handleValidation(req, res) {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
}


export const checkHealth = async (req, res, next) => {
    try {
        // 1. Prüfe die Datenbankverbindung mit einer einfachen, schnellen Abfrage


        // 2. Wenn alles gut geht, sende eine Erfolgsantwort
        res.status(200).json({
            status: 'ok',
            message: 'Service is running and database connection is healthy.'
        });
    } catch (error) {
        // 5. Wenn die DB-Abfrage fehlschlägt, sende einen Server-Fehler
        // Docker/Kubernetes wird dies als 'unhealthy' erkennen
        console.error('Health check failed:', error);
        res.status(503).json({ // 503 Service Unavailable
            status: 'error',
            message: 'Service is running, but database connection failed.'
        });
    }
};

export async function register(req, res) {
    if (handleValidation(req, res)) return;
    const { name, email, password } = req.body;

    const existing = await Model.findByEmail(email);
    if (existing) return res.status(409).json({ message: 'E-Mail bereits registriert' });

    const user = await Model.createAuthUser({ name, email, password });

    const accessToken = JWT.signAccessToken({ sub: user.user_id });
    const refreshToken = JWT.signRefreshToken({ sub: user.user_id });
    await Model.saveRefreshToken(user.user_id, refreshToken);

    res.set('Authorization', `Bearer ${accessToken}`);
    res.set('Access-Control-Expose-Headers', 'Authorization');
    res.status(201).json({
        refreshToken,
        userID: user.user_id // Added user_id here
    });                        // Body beliebig
}

export async function login(req, res) {
    if (handleValidation(req, res)) return;
    const { email, password } = req.body;

    const user = await Model.findByEmail(email);
    if (!user) return res.status(401).json({ message: 'Ungültige Anmeldedaten' });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ message: 'Ungültige Anmeldedaten' });

    const accessToken = JWT.signAccessToken({ sub: user.user_id });
    const refreshToken = JWT.signRefreshToken({ sub: user.user_id });
    await Model.saveRefreshToken(user.user_id, refreshToken);
    const userID = user.user_id;
    res.set('Authorization', `Bearer ${accessToken}`);
    res.set('Access-Control-Expose-Headers', 'Authorization'); // Add this line for CORS (if needed for login)
    res.json({ refreshToken , userID });
}

export async function refresh(req, res) {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(400).json({ message: 'refreshToken fehlt' });

    let payload;
    try {
        payload = JWT.verify(refreshToken);          // liefert { sub, iat, exp }
    } catch {
        return res.status(401).json({ message: 'Token ungültig' });
    }

    // jetzt per user_id suchen
    const user = await Model.findById(payload.sub);
    if (!user || user.refresh_token !== refreshToken) {
        return res.status(401).json({ message: 'Token abgelaufen' });
    }

    const accessToken = JWT.signAccessToken({ sub: payload.sub });
    res.set('Authorization', `Bearer ${accessToken}`);
    res.set('Access-Control-Expose-Headers', 'Authorization'); // Add this line for CORS (if needed for refresh)
    res.json('ok');
}


export async function logout(req, res) {    //5000:/auth/logout
    const { refreshToken } = req.body;
    await Model.invalidateRefreshToken(refreshToken);
    res.status(204).end();
}


export async function deleteUser(req, res, next) {
    // For security, get the user ID from the validated token, not the request body.
    const authHeader = req.headers['authorization'];
    const token = authHeader.split(' ')[1];
    const payload = JWT.verify(token, jwtSecret);

    const data = { user_id : payload.sub };
    const user_id = data.user_id;
    console.log(user_id);
    // Failsafe check to ensure middleware has provided a user ID.
    if (!user_id) {
        const err = new Error('User ID not found in token. Action is unauthorized.');
        err.status = 401;
        return next(err);
    }

    try {
        // Step 1: Delete the user's primary authentication record.
        // The Model.deleteUser function should return true on success, false on failure.
        const wasUserDeleted = await Model.deleteUser(user_id);

        if (!wasUserDeleted) {
            // This could happen if the user was already deleted.
            // We can choose to throw an error or log it and continue.
            const err = new Error('User to delete was not found in the auth database.');
            err.status = 404; // Not Found
            return next(err);
        }



        // On successful deletion and invalidation, return 204 No Content.
        return res.status(204).end();

    } catch (error) {
        // Pass any unexpected database or other errors to the global error handler.
        return next(error);
    }
}


export async function forgot(req, res) {
    //console.log('FORGOT called', req.body.email);

    const { email } = req.body;
    const user = await Model.findByEmail(email);
    if (!user) {
        //console.log('[forgot] email not found – ending'); //debug
        return res.status(404).end();
    }
    const rawToken = generateToken();
    const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
    await Model.saveResetToken(user.user_id, tokenHash, process.env.PASSWORD_RESET_TTL_MIN);
    await sendResetMail(email, rawToken);

    res.status(204).end();
}


export async function checkResetToken(req, res) {
    console.log('Checking reset token', req.params.token);
    const tokenHash = crypto.createHash('sha256').update(req.params.token).digest('hex');
    const user = await Model.findByResetToken(tokenHash);
    if (!user) return res.status(400).json({ message: 'invalid' });
    return res.sendStatus(200);
}

export async function resetPassword(req, res) {
    const { token, password } = req.body;
    console.log(token);
    console.log(password);
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const user = await Model.findByResetToken(tokenHash);
    if (!user) return res.status(400).json({ message: 'invalid' });

    await Model.updatePassword(user.user_id, password);   // bcrypt-hash
    await Model.clearResetToken(user.user_id);            // invalidate
    return res.sendStatus(204);
}

export async function verify(req, res) {
    const authHeader = req.headers['authorization'];    //unbdeingt klein
    //console.log('authHeader:', authHeader)


    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'Kein oder ungültiges Authorization-Header' });
    }

    const token = authHeader.split(' ')[1];
    //console.log('token!!!!:', token);
    try {
        //console.log('1:')
        const payload = JWT.verify(token, jwtSecret);
        // Verify the access token
        //console.log('2:')
        req.user = { userId: payload.sub }; // Attach user ID to the request
        //console.log('3:')
        res.status(200).json({
            message: 'Token gültig',
            user_id: payload.sub
        });      // Proceed to the next middleware or route handler
    } catch (error) {
        //console.log('40111:')
        return res.status(401).json({ message: 'Ungültiges Token' });
    }
}

export async function adminDeleteUser(req, res, next) {
    // 1. Get user ID to delete from request body
    const { user_id } = req.body;
    if (!user_id) {
        const err = new Error('User ID to delete is required');
        err.status = 400;
        return next(err);
    }

    // 2. Prevent self-deletion (optional security measure)
    if (user_id === req.user.id) {  // Now using req.user from middleware
        const err = new Error('Admins cannot delete themselves through this endpoint');
        err.status = 403;
        return next(err);
    }

    try {
        // 3. Delete the user's authentication record
        const wasUserDeleted = await Model.deleteUser(user_id);

        if (!wasUserDeleted) {
            const err = new Error('User to delete was not found in the auth database');
            err.status = 404;
            return next(err);
        }

        // 4. Return success (204 No Content)
        return res.status(204).end();

    } catch (error) {
        // 5. Handle errors
        error.status = error.status || 500;
        return next(error);
    }
}

export async function adminUpdate(req, res, next) {
    // 1. Get update data from request body
    const { user_id, updates } = req.body;
    console.log(user_id);
    // 2. Validate required fields
    if (!user_id || !updates) {
        const err = new Error('User ID and updates object are required');
        err.status = 400;
        console.error(err.message);
        return next(err);
    }

    // 3. Prevent self-updates of role/password (optional security measure)
    if (user_id === req.user.id && (updates.role || updates.password)) {
        const err = new Error('Admins cannot modify their own role or password through this endpoint');
        err.status = 403;
        console.error(err.message);
        return next(err);
    }

    try {
        // 4. Check if user exists
        const userExists = await Model.findById(user_id);
        if (!userExists) {
            const err = new Error('User not found');
            console.log('hello');
            err.status = 405;
            return next(err);
        }

        // 5. Process updates
        const updateResults = {};

        // Handle password update
        if (updates.password) {
            await Model.updatePassword(user_id, updates.password);
            updateResults.passwordUpdated = true;
        }

        // Handle role update
        if (updates.role) {
            if (!['admin', 'user', 'manager'].includes(updates.role)) { // Add your valid roles
                const err = new Error('Invalid role specified');
                err.status = 400;
                console.error(err.message);
                return next(err);
            }

            await Model.updateUserRole(user_id, updates.role);
            updateResults.roleUpdated = true;
        }

        // Handle other profile updates (email, name, etc.)
        if (updates.email || updates.name) {
            const profileUpdates = {};
            if (updates.email) profileUpdates.email = updates.email;
            if (updates.name) profileUpdates.name = updates.name;

            await Model.updateUserProfile(user_id, profileUpdates);
            updateResults.profileUpdated = true;
        }

        // 6. Return success
        return res.status(200).json({
            success: true,
            message: 'User updated successfully',
            updates: updateResults
        });

    } catch (error) {
        // 7. Handle errors
        error.status = error.status || 500;
        return next(error);
    }
}
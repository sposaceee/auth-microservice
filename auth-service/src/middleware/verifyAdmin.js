import { verify } from '../utils/jwt.js';
import { pool } from '../db.js';

export const verifyAdmin = async (req, res, next) => {
    try {
        // 1. Authorization Header prüfen
        const authHeader = req.headers['authorization'];
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                message: 'Authorization header missing or invalid',
                code: 'MISSING_AUTH_HEADER'
            });
        }

        // 2. Token verifizieren
        const token = authHeader.split(' ')[1];
        const decoded = verify(token);

        // 3. User-ID aus dem Token extrahieren
        const userId = decoded.sub;
        if (!userId) {
            return res.status(401).json({
                message: 'Invalid user ID in token',
                code: 'INVALID_USER_ID'
            });
        }
        console.log('mid1',userId); // richtige admin id alles super

        // 4. Datenbankabfrage um Admin-Status zu prüfen
        const { rows } = await pool.query(
            'SELECT role FROM auth_users WHERE user_id = $1',
            [userId]
        );

        if (rows.length === 0) {
            return res.status(404).json({
                message: 'User not found in database',
                code: 'USER_NOT_FOUND'
            });
        }

        // 5. Admin-Rolle prüfen
       // console.log('mide', rows[0].role); //user
        if (rows[0].role !== 'admin') {
            return res.status(403).json({
                message: 'Admin privileges required',
                code: 'ADMIN_ACCESS_REQUIRED',
                requiredRole: 'admin',
                currentRole: rows[0].role || 'none'
            });
        }

        // 6. User-Informationen an den Request anhängen
        req.user = {
            id: userId,
            role: rows[0].role,
            ...(decoded.email && { email: decoded.email })
        };

        next();
    } catch (error) {
        // Fehlerbehandlung
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({
                message: 'Token expired',
                code: 'TOKEN_EXPIRED',
                solution: 'Refresh your token or reauthenticate'
            });
        }

        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({
                message: 'Invalid token',
                code: 'INVALID_TOKEN',
                details: error.message
            });
        }

        console.error('Admin verification error:', error);
        return res.status(500).json({
            message: 'Internal server error during admin verification',
            code: 'ADMIN_VERIFICATION_FAILED'
        });
    }
};
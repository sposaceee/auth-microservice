import jwt from 'jsonwebtoken';

const {
    JWT_SECRET,
    ACCESS_TOKEN_EXPIRES_IN = 900,     // 15 min
    REFRESH_TOKEN_EXPIRES_IN = 1209600 // 14 Tage
} = process.env;

export function signAccessToken(payload) {
    return jwt.sign(payload, JWT_SECRET, { expiresIn: +ACCESS_TOKEN_EXPIRES_IN });
}

export function signRefreshToken(payload) {
    return jwt.sign(payload, JWT_SECRET, { expiresIn: +REFRESH_TOKEN_EXPIRES_IN });
}

export function verify(token) {
    return jwt.verify(token, JWT_SECRET);
}

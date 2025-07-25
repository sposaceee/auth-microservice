import crypto from 'crypto';
import nodemailer from 'nodemailer';
import * as dotenv from 'dotenv';
dotenv.config();


export function generateToken() {
    return crypto.randomBytes(32).toString('hex');           // 64 Zeichen
}

dotenv.config();

/* 1) Transporter nur EINMAL erstellen (Singleton) */
const transporter = nodemailer.createTransport(
    {
        host: process.env.EMAIL_HOST,
        port: +process.env.EMAIL_PORT,
        secure: +process.env.EMAIL_PORT === 465, // 465 = SSL, sonst STARTTLS
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS,
        },
    },
    /* Log-Optionen – zum Debuggen anschalten */
    { logger: false, debug: false }
);

/* 2) Hilfs-Funktion */
export async function sendResetMail(email, token) {

    const link = `${process.env.FRONTEND_BASE_URL}/reset-password?token=${token}`;
    // TODO FRONTEND_BASE_URL glue code not here but somewhere

    const mail = {
        from: `"Skala" <${process.env.EMAIL_USER}>`,
        to: email,
        subject: 'Passwort zurücksetzen',
        text: [
            'Du möchtest dein Passwort zurücksetzen.',
            `Öffne folgenden Link (gültig ${process.env.PASSWORD_RESET_TTL_MIN} Minuten):`,
            link,
            '',
            'Solltest du diese Anfrage nicht gestellt haben, ignoriere die Mail einfach.',
        ].join('\n'),
        html: `
      <p>Du möchtest dein Passwort zurücksetzen.</p>
      <p><a href="${link}">${link}</a></p>
      <p>Der Link ist ${process.env.PASSWORD_RESET_TTL_MIN} Minuten gültig.</p>
      <p>Falls du die Anfrage nicht gestellt hast, kannst du diese Mail ignorieren.</p>
    `,
    };

    try {
        const info = await transporter.sendMail(mail);
        /* optional log */
        console.log('Reset-Mail verschickt:', info.messageId);
    } catch (err) {
        /* 3) Fehler weiterreichen – wird in deiner Error-Middleware geloggt */
        console.error('E-Mail-Versand fehlgeschlagen:', err);
        throw new Error('MailDeliveryFailed');
    }
}

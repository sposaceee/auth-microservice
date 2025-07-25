import express from 'express';
import cors from 'cors';
import * as dotenv from 'dotenv';
import authRoutes from './routes/auth.routes.js';

dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());

app.get('/health', (_, res) => res.json('ok'));
app.use('/auth', authRoutes);

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Auth-service listening on ${PORT}`));

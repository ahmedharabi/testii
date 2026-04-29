import express, { Request, Response, NextFunction } from 'express';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { z } from 'zod';
import multer from 'multer';
import cron from 'node-cron';

const app = express();
app.use(express.json());

const port = process.env.PORT || 3000;
const prisma = new PrismaClient();
const JWT_SECRET = process.env.JWT_SECRET || 'supersecret';

// Configure multer
const upload = multer({ dest: 'uploads/' });

// Zod schemas
const registerSchema = z.object({
    email: z.string().email(),
    password: z.string().min(6)
});

const loginSchema = z.object({
    email: z.string().email(),
    password: z.string()
});

// Middleware
const authenticate = (req: Request, res: Response, next: NextFunction): void => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        res.status(401).json({ error: 'No token provided' });
        return;
    }

    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, JWT_SECRET) as { userId: number };
        (req as any).user = decoded;
        next();
    } catch (err) {
        res.status(401).json({ error: 'Invalid token' });
        return;
    }
};

// Existing Endpoints
app.get('/', (req: Request, res: Response) => {
    res.json({ message: "hello world" });
});

app.get('/health', (req: Request, res: Response) => {
    res.json({ status: "ok" });
});

// Auth Endpoints
app.post('/auth/register', async (req: Request, res: Response): Promise<void> => {
    try {
        const { email, password } = registerSchema.parse(req.body);

        const existingUser = await prisma.user.findUnique({ where: { email } });
        if (existingUser) {
            res.status(400).json({ error: 'User already exists' });
            return;
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = await prisma.user.create({
            data: {
                email,
                password: hashedPassword,
            },
        });

        res.status(201).json({ message: 'User registered successfully', userId: user.id });
    } catch (error) {
        res.status(400).json({ error: 'Invalid request', details: error });
    }
});

app.post('/auth/login', async (req: Request, res: Response): Promise<void> => {
    try {
        const { email, password } = loginSchema.parse(req.body);

        const user = await prisma.user.findUnique({ where: { email } });
        if (!user) {
            res.status(401).json({ error: 'Invalid credentials' });
            return;
        }

        const isValid = await bcrypt.compare(password, user.password);
        if (!isValid) {
            res.status(401).json({ error: 'Invalid credentials' });
            return;
        }

        const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (error) {
        res.status(400).json({ error: 'Invalid request', details: error });
    }
});

// Protected User Endpoint
app.get('/users/me', authenticate, async (req: Request, res: Response): Promise<void> => {
    const userId = (req as any).user.userId;
    const user = await prisma.user.findUnique({ where: { id: userId } });

    if (!user) {
        res.status(404).json({ error: 'User not found' });
        return;
    }

    const { password, ...userWithoutPassword } = user;
    res.json(userWithoutPassword);
});

// Protected Upload Endpoint
app.post('/upload', authenticate, upload.single('file'), (req: Request, res: Response): void => {
    if (!req.file) {
        res.status(400).json({ error: 'No file uploaded' });
        return;
    }
    res.json({ message: 'File uploaded successfully', filename: req.file.filename });
});

// Cron Job
cron.schedule('* * * * *', () => {
    console.log('tick');
});

// Start Server
app.listen(port, () => {
    console.log(`Server is listening on port ${port}`);
});

"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const client_1 = require("@prisma/client");
const bcrypt_1 = __importDefault(require("bcrypt"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const zod_1 = require("zod");
const multer_1 = __importDefault(require("multer"));
const node_cron_1 = __importDefault(require("node-cron"));
const app = (0, express_1.default)();
app.use(express_1.default.json());
const port = process.env.PORT || 3000;
const prisma = new client_1.PrismaClient();
const JWT_SECRET = process.env.JWT_SECRET || 'supersecret';
// Configure multer
const upload = (0, multer_1.default)({ dest: 'uploads/' });
// Zod schemas
const registerSchema = zod_1.z.object({
    email: zod_1.z.string().email(),
    password: zod_1.z.string().min(6)
});
const loginSchema = zod_1.z.object({
    email: zod_1.z.string().email(),
    password: zod_1.z.string()
});
// Middleware
const authenticate = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        res.status(401).json({ error: 'No token provided' });
        return;
    }
    const token = authHeader.split(' ')[1];
    try {
        const decoded = jsonwebtoken_1.default.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    }
    catch (err) {
        res.status(401).json({ error: 'Invalid token' });
        return;
    }
};
// Existing Endpoints
app.get('/', (req, res) => {
    res.json({ message: "hello world" });
});
app.get('/health', (req, res) => {
    res.json({ status: "ok" });
});
// Auth Endpoints
app.post('/auth/register', async (req, res) => {
    try {
        const { email, password } = registerSchema.parse(req.body);
        const existingUser = await prisma.user.findUnique({ where: { email } });
        if (existingUser) {
            res.status(400).json({ error: 'User already exists' });
            return;
        }
        const hashedPassword = await bcrypt_1.default.hash(password, 10);
        const user = await prisma.user.create({
            data: {
                email,
                password: hashedPassword,
            },
        });
        res.status(201).json({ message: 'User registered successfully', userId: user.id });
    }
    catch (error) {
        res.status(400).json({ error: 'Invalid request', details: error });
    }
});
app.post('/auth/login', async (req, res) => {
    try {
        const { email, password } = loginSchema.parse(req.body);
        const user = await prisma.user.findUnique({ where: { email } });
        if (!user) {
            res.status(401).json({ error: 'Invalid credentials' });
            return;
        }
        const isValid = await bcrypt_1.default.compare(password, user.password);
        if (!isValid) {
            res.status(401).json({ error: 'Invalid credentials' });
            return;
        }
        const token = jsonwebtoken_1.default.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    }
    catch (error) {
        res.status(400).json({ error: 'Invalid request', details: error });
    }
});
// Protected User Endpoint
app.get('/users/me', authenticate, async (req, res) => {
    const userId = req.user.userId;
    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
        res.status(404).json({ error: 'User not found' });
        return;
    }
    const { password, ...userWithoutPassword } = user;
    res.json(userWithoutPassword);
});
// Protected Upload Endpoint
app.post('/upload', authenticate, upload.single('file'), (req, res) => {
    if (!req.file) {
        res.status(400).json({ error: 'No file uploaded' });
        return;
    }
    res.json({ message: 'File uploaded successfully', filename: req.file.filename });
});
// Cron Job
node_cron_1.default.schedule('* * * * *', () => {
    console.log('tick');
});
// Start Server
app.listen(port, () => {
    console.log(`Server is listening on port ${port}`);
});

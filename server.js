// server.js - Node.js/Express + MongoDB backend
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/codeexanalytics', {
    useNewUrlParser: true,
    useUnifiedTopology: true
});

// MongoDB Schemas
const userSchema = new mongoose.Schema({
    id: { type: String, unique: true, required: true },
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    email: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['admin', 'employee'], default: 'employee' },
    department: { type: String, default: 'General' },
    position: { type: String, default: '' },
    employeeId: { type: String, unique: true },
    createdAt: { type: Date, default: Date.now }
});

const timeRecordSchema = new mongoose.Schema({
    id: { type: String, unique: true, required: true },
    userId: { type: String, required: true },
    userName: { type: String, required: true },
    userEmail: { type: String, required: true },
    project: { type: String, required: true },
    task: { type: String, required: true },
    startTime: { type: Date, required: true },
    endTime: { type: Date },
    duration: { type: String },
    durationSeconds: { type: Number },
    isRunning: { type: Boolean, default: false },
    isPaused: { type: Boolean, default: false },
    isManual: { type: Boolean, default: false },
    date: { type: String, required: true },
    recordedAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const TimeRecord = mongoose.model('TimeRecord', timeRecordSchema);

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this';

// Middleware to verify JWT
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) return res.sendStatus(401);
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// ==================== AUTHENTICATION ENDPOINTS ====================

// Admin Login
app.post('/api/admin/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        const user = await User.findOne({ email, role: 'admin' });
        if (!user) return res.status(404).json({ error: 'Admin account not found' });
        
        const validPassword = user.password === password; // In production, use bcrypt.compare
        if (!validPassword) return res.status(401).json({ error: 'Invalid password' });
        
        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role },
            JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        res.json({
            token,
            user: {
                id: user.id,
                firstName: user.firstName,
                lastName: user.lastName,
                email: user.email,
                role: user.role,
                department: user.department,
                position: user.position,
                employeeId: user.employeeId
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Employee Login
app.post('/api/employee/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        const user = await User.findOne({ email, role: 'employee' });
        if (!user) return res.status(404).json({ error: 'Employee account not found' });
        
        const validPassword = user.password === password;
        if (!validPassword) return res.status(401).json({ error: 'Invalid password' });
        
        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role },
            JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        res.json({
            token,
            user: {
                id: user.id,
                firstName: user.firstName,
                lastName: user.lastName,
                email: user.email,
                role: user.role,
                department: user.department,
                position: user.position,
                employeeId: user.employeeId
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== ADMIN ENDPOINTS ====================

// Get all employees (admin only)
app.get('/api/admin/employees', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied' });
        
        const employees = await User.find({ role: 'employee' });
        res.json(employees);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Add new employee (admin only)
app.post('/api/admin/employees', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied' });
        
        const { firstName, lastName, email, password, department, position } = req.body;
        
        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(400).json({ error: 'Email already exists' });
        
        const employeeCount = await User.countDocuments({ role: 'employee' });
        const employeeId = `EMP${(employeeCount + 1).toString().padStart(3, '0')}`;
        
        const newEmployee = new User({
            id: 'emp_' + Date.now(),
            firstName,
            lastName,
            email,
            password, // In production, hash with bcrypt
            role: 'employee',
            department,
            position,
            employeeId
        });
        
        await newEmployee.save();
        res.status(201).json(newEmployee);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Delete employee (admin only)
app.delete('/api/admin/employees/:id', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied' });
        
        const { id } = req.params;
        
        // Delete employee
        await User.findOneAndDelete({ id });
        
        // Delete all time records for this employee
        await TimeRecord.deleteMany({ userId: id });
        
        res.json({ message: 'Employee deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get all time records (admin only)
app.get('/api/admin/records', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied' });
        
        const { dateRange, employeeId, project } = req.query;
        
        let query = { isRunning: false };
        
        // Apply filters
        if (dateRange === 'today') {
            const today = new Date().toISOString().split('T')[0];
            query.date = today;
        } else if (dateRange === 'week') {
            const startOfWeek = new Date();
            startOfWeek.setDate(startOfWeek.getDate() - startOfWeek.getDay() + 1);
            query.date = { $gte: startOfWeek.toISOString().split('T')[0] };
        } else if (dateRange === 'month') {
            const startOfMonth = new Date();
            startOfMonth.setDate(1);
            query.date = { $gte: startOfMonth.toISOString().split('T')[0] };
        }
        
        if (employeeId && employeeId !== 'all') {
            query.userId = employeeId;
        }
        
        if (project && project !== 'all') {
            query.project = project;
        }
        
        const records = await TimeRecord.find(query)
            .sort({ startTime: -1 })
            .limit(100);
        
        res.json(records);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get dashboard stats (admin only)
app.get('/api/admin/dashboard/stats', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied' });
        
        const today = new Date().toISOString().split('T')[0];
        const startOfWeek = new Date();
        startOfWeek.setDate(startOfWeek.getDate() - startOfWeek.getDay() + 1);
        
        // Today's records
        const todayRecords = await TimeRecord.find({ 
            date: today,
            isRunning: false 
        });
        
        // Weekly records
        const weekRecords = await TimeRecord.find({
            date: { $gte: startOfWeek.toISOString().split('T')[0] },
            isRunning: false
        });
        
        // Active timers
        const activeTimers = await TimeRecord.countDocuments({ isRunning: true });
        
        // Employee stats
        const totalEmployees = await User.countDocuments({ role: 'employee' });
        const employeesActiveToday = new Set(todayRecords.map(r => r.userId)).size;
        
        const stats = {
            totalHoursToday: (todayRecords.reduce((sum, r) => sum + (r.durationSeconds || 0), 0) / 3600).toFixed(1),
            weeklyTotal: (weekRecords.reduce((sum, r) => sum + (r.durationSeconds || 0), 0) / 3600).toFixed(1),
            activeTimersNow: activeTimers,
            daysThisWeek: new Set(weekRecords.map(r => r.date)).size,
            totalTeamMembers: totalEmployees,
            activeToday: employeesActiveToday,
            avgHoursPerDay: (weekRecords.reduce((sum, r) => sum + (r.durationSeconds || 0), 0) / 3600 / 
                            Math.max(1, new Set(weekRecords.map(r => r.date)).size)).toFixed(1)
        };
        
        res.json(stats);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== EMPLOYEE ENDPOINTS ====================

// Get employee's time records
app.get('/api/employee/records', authenticateToken, async (req, res) => {
    try {
        const { dateRange, project } = req.query;
        
        let query = { 
            userId: req.user.id,
            isRunning: false 
        };
        
        if (dateRange === 'today') {
            const today = new Date().toISOString().split('T')[0];
            query.date = today;
        } else if (dateRange === 'week') {
            const startOfWeek = new Date();
            startOfWeek.setDate(startOfWeek.getDate() - startOfWeek.getDay() + 1);
            query.date = { $gte: startOfWeek.toISOString().split('T')[0] };
        } else if (dateRange === 'month') {
            const startOfMonth = new Date();
            startOfMonth.setDate(1);
            query.date = { $gte: startOfMonth.toISOString().split('T')[0] };
        }
        
        if (project && project !== 'all') {
            query.project = project;
        }
        
        const records = await TimeRecord.find(query).sort({ startTime: -1 });
        res.json(records);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Start timer
app.post('/api/employee/timer/start', authenticateToken, async (req, res) => {
    try {
        const { project, task } = req.body;
        
        // Check if already has active timer
        const existingTimer = await TimeRecord.findOne({ 
            userId: req.user.id, 
            isRunning: true 
        });
        
        if (existingTimer) {
            return res.status(400).json({ error: 'Timer already running' });
        }
        
        const user = await User.findOne({ id: req.user.id });
        
        const newTimer = new TimeRecord({
            id: 'timer_' + Date.now(),
            userId: req.user.id,
            userName: `${user.firstName} ${user.lastName}`,
            userEmail: user.email,
            project,
            task,
            startTime: new Date(),
            isRunning: true,
            isPaused: false,
            date: new Date().toISOString().split('T')[0]
        });
        
        await newTimer.save();
        res.status(201).json(newTimer);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Stop timer
app.post('/api/employee/timer/stop/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        
        const timer = await TimeRecord.findOne({ id, userId: req.user.id });
        if (!timer) return res.status(404).json({ error: 'Timer not found' });
        
        const endTime = new Date();
        const durationSeconds = Math.floor((endTime - new Date(timer.startTime)) / 1000);
        
        timer.endTime = endTime;
        timer.duration = formatDuration(durationSeconds);
        timer.durationSeconds = durationSeconds;
        timer.isRunning = false;
        
        await timer.save();
        res.json(timer);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Pause/Resume timer
app.post('/api/employee/timer/pause/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { action } = req.body; // 'pause' or 'resume'
        
        const timer = await TimeRecord.findOne({ id, userId: req.user.id });
        if (!timer) return res.status(404).json({ error: 'Timer not found' });
        
        if (action === 'pause') {
            timer.isPaused = true;
        } else if (action === 'resume') {
            timer.isPaused = false;
        }
        
        await timer.save();
        res.json(timer);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Add manual time entry
app.post('/api/employee/records/manual', authenticateToken, async (req, res) => {
    try {
        const { project, task, startTime, endTime } = req.body;
        
        const user = await User.findOne({ id: req.user.id });
        const durationSeconds = Math.floor((new Date(endTime) - new Date(startTime)) / 1000);
        
        const newRecord = new TimeRecord({
            id: 'manual_' + Date.now(),
            userId: req.user.id,
            userName: `${user.firstName} ${user.lastName}`,
            userEmail: user.email,
            project,
            task,
            startTime: new Date(startTime),
            endTime: new Date(endTime),
            duration: formatDuration(durationSeconds),
            durationSeconds,
            isRunning: false,
            isManual: true,
            date: new Date(startTime).toISOString().split('T')[0]
        });
        
        await newRecord.save();
        res.status(201).json(newRecord);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get employee dashboard stats
app.get('/api/employee/dashboard/stats', authenticateToken, async (req, res) => {
    try {
        const today = new Date().toISOString().split('T')[0];
        const startOfWeek = new Date();
        startOfWeek.setDate(startOfWeek.getDate() - startOfWeek.getDay() + 1);
        
        // Today's records
        const todayRecords = await TimeRecord.find({ 
            userId: req.user.id,
            date: today,
            isRunning: false 
        });
        
        // Weekly records
        const weekRecords = await TimeRecord.find({
            userId: req.user.id,
            date: { $gte: startOfWeek.toISOString().split('T')[0] },
            isRunning: false
        });
        
        // Active timer
        const activeTimer = await TimeRecord.findOne({ 
            userId: req.user.id,
            isRunning: true 
        });
        
        const stats = {
            todayHours: (todayRecords.reduce((sum, r) => sum + (r.durationSeconds || 0), 0) / 3600).toFixed(1),
            todaySessions: todayRecords.length,
            weeklyTotal: (weekRecords.reduce((sum, r) => sum + (r.durationSeconds || 0), 0) / 3600).toFixed(1),
            daysThisWeek: new Set(weekRecords.map(r => r.date)).size,
            currentStatus: activeTimer ? (activeTimer.isPaused ? 'Paused' : 'Working') : 'Not Working',
            statusDetail: activeTimer ? `On: ${activeTimer.task}` : 'Ready to start tracking',
            productivityScore: calculateProductivityScore(weekRecords)
        };
        
        res.json(stats);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== UTILITY FUNCTIONS ====================

function formatDuration(totalSeconds) {
    const hours = Math.floor(totalSeconds / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    const seconds = totalSeconds % 60;
    
    if (hours > 0) {
        return `${hours}h ${minutes}m`;
    } else if (minutes > 0) {
        return `${minutes}m ${seconds}s`;
    } else {
        return `${seconds}s`;
    }
}

function calculateProductivityScore(weekRecords) {
    const totalHours = weekRecords.reduce((sum, r) => sum + (r.durationSeconds || 0), 0) / 3600;
    const targetHours = 40; // 8 hours/day * 5 days
    const score = Math.min((totalHours / targetHours) * 100, 100);
    return Math.round(score);
}

// ==================== INITIALIZATION ====================

// Initialize admin user if none exists
async function initializeAdmin() {
    try {
        const adminExists = await User.findOne({ role: 'admin' });
        
        if (!adminExists) {
            const admin = new User({
                id: 'admin_001',
                firstName: 'Admin',
                lastName: 'User',
                email: 'admin@codeexanalytics.com',
                password: 'admin123',
                role: 'admin',
                department: 'Administration',
                position: 'System Administrator',
                employeeId: 'ADM001'
            });
            
            await admin.save();
            console.log('Admin user created');
        }
    } catch (error) {
        console.error('Error initializing admin:', error);
    }
}

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, async () => {
    console.log(`Server running on port ${PORT}`);
    await initializeAdmin();
});

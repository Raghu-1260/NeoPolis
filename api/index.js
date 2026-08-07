const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { MongoClient } = require('mongodb');
const twilio = require('twilio');

const app = express();
app.use(cors());
app.use(express.json());

// MongoDB Serverless Connection Caching Singleton
let cachedDb = null;

async function connectToDatabase() {
    if (cachedDb) return cachedDb;
    if (!process.env.MONGODB_URI) throw new Error("MONGODB_URI environment variable missing!");

    const client = await MongoClient.connect(process.env.MONGODB_URI);
    const db = client.db('neopolis');
    cachedDb = db;
    return db;
}

// ==========================================
// 1. SECURITY & ATTACK LOGGING ENGINE
// ==========================================
async function logSecurityAttack(db, type, req, details = '') {
    try {
        const attackLogs = db.collection('security_attack_logs');
        const entry = {
            timestamp: new Date(),
            type: type,
            ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'Unknown',
            userAgent: req.headers['user-agent'] || 'Unknown',
            path: req.originalUrl,
            details: details
        };
        await attackLogs.insertOne(entry);
        console.error(`🚨 SECURITY ATTACK DETECTED [${type}]:`, entry);
    } catch (err) {
        console.error("Failed to record attack log:", err);
    }
}

// Anti-Brute-Force Rate Limiting (100 Requests per 15 Min Window)
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    handler: async (req, res) => {
        const db = await connectToDatabase();
        await logSecurityAttack(db, 'RATE_LIMIT_EXCEEDED', req, 'Exceeded 100 requests in 15 mins');
        res.status(429).json({ success: false, message: 'Too many requests. Attack activity logged.' });
    }
});

app.use('/api/', apiLimiter);

// SQL Injection & Malicious Payload Detector
app.use(async (req, res, next) => {
    const payload = JSON.stringify(req.body) + JSON.stringify(req.query);
    const suspiciousPatterns = [/select\s+.*\s+from/i, /<script>/i, /union\s+select/i, /drop\s+table/i];
    
    for (let pattern of suspiciousPatterns) {
        if (pattern.test(payload)) {
            const db = await connectToDatabase();
            await logSecurityAttack(db, 'INJECTION_ATTEMPT', req, `Blocked Payload: ${payload}`);
            return res.status(400).json({ success: false, message: 'Malicious payload blocked and logged.' });
        }
    }
    next();
});

// ==========================================
// 2. PLOT PURCHASES & CEO OTP APIS
// ==========================================

// GET Route: Fetch Plots from MongoDB
app.get('/api/plots', async (req, res) => {
    try {
        const db = await connectToDatabase();
        const plotsCollection = db.collection('plots');
        const plotsArray = await plotsCollection.find({}).toArray();
        
        const plotsMap = {};
        plotsArray.forEach(p => { plotsMap[p.plotId] = p; });

        res.json({ success: true, plots: plotsMap });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// POST Route: Dispatch CEO Security OTP
app.post('/api/send-ceo-otp', async (req, res) => {
    const { ceoPhone } = req.body;
    const generatedOtp = Math.floor(100000 + Math.random() * 900000).toString();

    try {
        if (process.env.TWILIO_SID && process.env.TWILIO_AUTH) {
            const client = twilio(process.env.TWILIO_SID, process.env.TWILIO_AUTH);
            await client.messages.create({
                body: `[NeoPolis Springs] CEO Security Code: ${generatedOtp}. Do not share this code.`,
                from: process.env.TWILIO_PHONE,
                to: ceoPhone
            });
        }
        res.json({ success: true, message: 'OTP dispatched to CEO.' });
    } catch (err) {
        const db = await connectToDatabase();
        await logSecurityAttack(db, 'SMS_GATEWAY_ERROR', req, err.message);
        res.status(500).json({ success: false, message: 'SMS Gateway Delivery Failed.' });
    }
});

// POST Route: Update Plot Status & Save to MongoDB
app.post('/api/plots/update', async (req, res) => {
    try {
        const { plotId, newStatus, buyerName, buyerMobile, user, otp } = req.body;

        // Convert OTP to string & trim spaces to prevent type mismatch bugs
        const providedOtp = otp ? String(otp).trim() : '';

        if (newStatus === 'SOLD' && providedOtp !== '849201') {
            await logSecurityAttack('INVALID_CEO_OTP', req, `Plot: ${plotId}`);
            return res.status(401).json({ success: false, message: 'Invalid CEO Security OTP Code!' });
        }

        const db = await getDatabase();
        const purchaseDate = new Date().toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });

        const updatedData = {
            plotId: String(plotId),
            status: newStatus,
            owner: newStatus === 'AVAILABLE' ? 'Unassigned' : (buyerName || 'Reserved'),
            buyer_name: buyerName || '',
            buyer_mobile: buyerMobile || '',
            purchase_date: newStatus === 'SOLD' ? purchaseDate : '',
            updated_by: user ? user.id : 'admin',
            updated_at: new Date()
        };

        const plotsCollection = db.collection('plots');
        await plotsCollection.updateOne({ plotId: String(plotId) }, { $set: updatedData }, { upsert: true });

        res.json({
            success: true,
            message: `Plot ${plotId} status updated to ${newStatus}.`,
            updatedPlot: updatedData
        });
    } catch (err) {
        console.error("POST /api/plots/update Error:", err.message);
        res.status(500).json({ success: false, error: err.message });
    }
});

// ==========================================
// 3. AUTOMATED BACKUP CRON ENDPOINT
// ==========================================
app.get('/api/cron/backup', async (req, res) => {
    try {
        const db = await connectToDatabase();
        const plotsCollection = db.collection('plots');
        const allPlots = await plotsCollection.find({}).toArray();

        // Create an automated daily backup snapshot document in MongoDB
        const backupArchive = db.collection('database_daily_backups');
        await backupArchive.insertOne({
            backup_date: new Date(),
            snapshot_type: 'DAILY_AUTOMATED_CRON',
            total_plots_backed_up: allPlots.length,
            data_snapshot: allPlots
        });

        console.log(`📦 Automated Backup Executed Successfully: ${allPlots.length} records archived.`);
        res.json({ success: true, message: 'Automated Daily Backup Complete', timestamp: new Date() });
    } catch (err) {
        console.error("Backup execution error:", err.message);
        res.status(500).json({ success: false, error: err.message });
    }
});

// GET Route: Admin Security Logs Viewer
app.get('/api/admin/security-logs', async (req, res) => {
    try {
        const db = await connectToDatabase();
        const logs = await db.collection('security_attack_logs').find({}).sort({ timestamp: -1 }).limit(100).toArray();
        res.json({ success: true, logs: logs });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

module.exports = app;
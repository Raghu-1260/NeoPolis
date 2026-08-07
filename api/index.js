const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { MongoClient } = require('mongodb');
const twilio = require('twilio');

const app = express();
app.use(cors());
app.use(express.json());

// Singleton MongoDB Connection Helper
let cachedClient = null;

async function getDatabase() {
    if (cachedClient && cachedClient.topology && cachedClient.topology.isConnected()) {
        return cachedClient.db('neopolis');
    }

    const uri = process.env.MONGODB_URI;
    if (!uri) {
        throw new Error("MONGODB_URI environment variable is missing on Vercel!");
    }

    const client = new MongoClient(uri);
    await client.connect();
    cachedClient = client;
    return client.db('neopolis');
}

// Security Attack Logger
async function logSecurityAttack(type, req, details = '') {
    try {
        const db = await getDatabase();
        const attackLogs = db.collection('security_attack_logs');
        await attackLogs.insertOne({
            timestamp: new Date(),
            type: type,
            ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'Unknown',
            userAgent: req.headers['user-agent'] || 'Unknown',
            path: req.originalUrl,
            details: details
        });
    } catch (err) {
        console.error("Failed to write attack log:", err.message);
    }
}

// Anti-Brute-Force Rate Limiting
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    handler: async (req, res) => {
        await logSecurityAttack('RATE_LIMIT_EXCEEDED', req, 'Exceeded 100 requests in 15 mins');
        res.status(429).json({ success: false, message: 'Too many requests.' });
    }
});

app.use('/api/', apiLimiter);

// SQL Injection & Malicious Payload Detector
app.use(async (req, res, next) => {
    const payload = JSON.stringify(req.body) + JSON.stringify(req.query);
    const suspiciousPatterns = [/select\s+.*\s+from/i, /<script>/i, /union\s+select/i, /drop\s+table/i];
    
    for (let pattern of suspiciousPatterns) {
        if (pattern.test(payload)) {
            await logSecurityAttack('INJECTION_ATTEMPT', req, `Blocked Payload: ${payload}`);
            return res.status(400).json({ success: false, message: 'Malicious payload blocked.' });
        }
    }
    next();
});

// ==========================================
// API ENDPOINTS
// ==========================================

// GET: Fetch Plots
app.get('/api/plots', async (req, res) => {
    try {
        const db = await getDatabase();
        const plotsCollection = db.collection('plots');
        const plotsArray = await plotsCollection.find({}).toArray();
        
        const plotsMap = {};
        plotsArray.forEach(p => { plotsMap[p.plotId] = p; });

        res.json({ success: true, plots: plotsMap });
    } catch (err) {
        console.error("GET /api/plots Error:", err.message);
        res.status(500).json({ success: false, message: err.message });
    }
});

// POST: Update Plot & Verify CEO OTP
app.post('/api/plots/update', async (req, res) => {
    try {
        const { plotId, newStatus, buyerName, buyerMobile, user, otp } = req.body;

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

        // Optional SMS Dispatch
        if (newStatus === 'SOLD' && buyerMobile && process.env.TWILIO_SID) {
            try {
                const client = twilio(process.env.TWILIO_SID, process.env.TWILIO_AUTH);
                await client.messages.create({
                    body: `Dear ${buyerName}, Booking for Plot No. ${plotId} at NeoPolis Springs is confirmed on ${purchaseDate}. Thank you!`,
                    from: process.env.TWILIO_PHONE,
                    to: `+91${buyerMobile}`
                });
            } catch (smsErr) {
                console.warn("SMS Error:", smsErr.message);
            }
        }

        res.json({
            success: true,
            message: `Plot ${plotId} status updated to ${newStatus}.`,
            updatedPlot: updatedData
        });
    } catch (err) {
        console.error("POST /api/plots/update Error:", err.message);
        res.status(500).json({ success: false, message: err.message });
    }
});

// GET: Cron Daily Backup
app.get('/api/cron/backup', async (req, res) => {
    try {
        const db = await getDatabase();
        const plotsCollection = db.collection('plots');
        const allPlots = await plotsCollection.find({}).toArray();

        const backupArchive = db.collection('database_daily_backups');
        await backupArchive.insertOne({
            backup_date: new Date(),
            snapshot_type: 'DAILY_AUTOMATED_CRON',
            total_plots_backed_up: allPlots.length,
            data_snapshot: allPlots
        });

        res.json({ success: true, message: 'Automated Daily Backup Complete', timestamp: new Date() });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// GET: Admin Logs
app.get('/api/admin/security-logs', async (req, res) => {
    try {
        const db = await getDatabase();
        const logs = await db.collection('security_attack_logs').find({}).sort({ timestamp: -1 }).limit(100).toArray();
        res.json({ success: true, logs: logs });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

module.exports = app;
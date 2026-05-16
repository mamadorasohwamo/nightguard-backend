/**
 * NightGuard AC Backend API v3
 * Professional Anti-Cheat Management Server
 */

const express = require('express');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 8080;

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' })); // Allow large scan results

// In-Memory Storage (Use Database like MongoDB/PostgreSQL for production persistence)
let activePins = [];
let scanSessions = [];
let systemSettings = {
    realTimeScan: true,
    browserMonitoring: true,
    discordMonitoring: true,
    archiveScanning: true,
    dllScanning: true,
    telemetry: true,
    autoBan: false,
    pinExpiryMinutes: 60
};

// --- API ROUTES ---

// Health Check
app.get('/', (req, res) => res.send("NightGuard API Online v3"));

// 1. PIN SYSTEM
app.post('/api/pin/generate', (req, res) => {
    try {
        const rawUuid = uuidv4();
        const pin = `NG-${rawUuid.split('-')[0].toUpperCase()}-${Math.floor(1000 + Math.random() * 9000)}`;

        activePins.push({
            pin: pin,
            hwid: null,
            createdAt: Date.now(),
            expiresAt: Date.now() + (systemSettings.pinExpiryMinutes * 60 * 1000),
            used: false
        });

        console.log(`[PIN] Generated: ${pin}`);
        res.json({ success: true, pin: pin });
    } catch (error) {
        res.status(500).json({ success: false, message: "Generation failed" });
    }
});

app.post('/api/pin/validate', (req, res) => {
    const { pin, hwid } = req.body;
    const foundPin = activePins.find(p => p.pin === pin);

    if (!foundPin) return res.status(401).json({ success: false, error: "invalid_pin" });
    if (Date.now() > foundPin.expiresAt) return res.status(401).json({ success: false, error: "expired_pin" });
    if (foundPin.used) return res.status(403).json({ success: false, error: "used_pin" });

    // HWID Binding
    if (!foundPin.hwid) {
        foundPin.hwid = hwid;
    } else if (foundPin.hwid !== hwid) {
        return res.status(403).json({ success: false, error: "hwid_mismatch" });
    }

    foundPin.used = true;
    console.log(`[VERIFY] PIN ${pin} validated for HWID ${hwid}`);
    res.json({ success: true, status: "verified" });
});

// 2. LOG SYSTEM
app.get('/api/logs', (req, res) => {
    res.json({ success: true, logs: scanSessions });
});

app.get('/api/logs/:id', (req, res) => {
    const session = scanSessions.find(s => s.sessionId === req.params.id);
    if (session) {
        res.json({ success: true, session });
    } else {
        res.status(404).json({ success: false, message: "Session not found" });
    }
});

app.post('/api/scan/result', (req, res) => {
    const data = req.body;
    
    const newSession = {
        sessionId: uuidv4().slice(0, 12).toUpperCase(),
        pin: data.pin || 'N/A',
        discordId: data.discordId || 'N/A',
        discordUsername: data.discordUsername || 'Guest',
        pcName: data.pcName || 'Unknown PC',
        hwid: data.hwid || 'N/A',
        scanTime: new Date(),
        riskLevel: data.riskLevel || 0,
        detections: data.detections || [], // Full detection list
        browserFindings: data.browserFindings || [],
        discordFindings: data.discordFindings || [],
        suspiciousFiles: data.suspiciousFiles || [],
        suspiciousDlls: data.suspiciousDlls || [],
        suspiciousArchives: data.suspiciousArchives || [],
        registryChanges: data.registryChanges || [],
        status: (data.riskLevel > 50) ? "FLAGGED" : "SECURE"
    };

    scanSessions.unshift(newSession);
    if (scanSessions.length > 1000) scanSessions.pop(); // Keep last 1000

    console.log(`[SCAN] Result received from ${newSession.pcName} (Risk: ${newSession.riskLevel}%)`);
    res.json({ success: true, sessionId: newSession.sessionId });
});

// 3. SYSTEM STATS & SETTINGS
app.get('/api/stats', (req, res) => {
    res.json({
        success: true,
        stats: {
            totalScans: scanSessions.length,
            flaggedScans: scanSessions.filter(s => s.status === "FLAGGED").length,
            uniqueUsers: new Set(scanSessions.map(s => s.hwid)).size,
            activePins: activePins.filter(p => !p.used && p.expiresAt > Date.now()).length,
            uptime: process.uptime()
        }
    });
});

app.get('/api/settings', (req, res) => res.json(systemSettings));
app.post('/api/settings', (req, res) => {
    systemSettings = { ...systemSettings, ...req.body };
    res.json({ success: true, settings: systemSettings });
});

// --- HELPERS ---

// Auto Cleanup Expired PINs every 10 mins
setInterval(() => {
    const now = Date.now();
    activePins = activePins.filter(p => p.expiresAt > now || !p.used);
}, 10 * 60 * 1000);

// Start Server
app.listen(PORT, () => {
    console.log(`=========================================`);
    console.log(`NightGuard AC Backend v3 - Online`);
    console.log(`Port: ${PORT}`);
    console.log(`=========================================`);
});

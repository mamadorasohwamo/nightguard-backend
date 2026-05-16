/**
 * NightGuard AC Backend API
 * Production-ready Express server for PIN management
 */

const express = require('express');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 8080;

// Enable CORS for frontend integration
app.use(cors());

// Support JSON payloads
app.use(express.json());

/**
 * Route: GET /
 * Simple health check
 */
app.get('/', (req, res) => {
    res.send("NightGuard API Online");
});

/**
 * Route: POST /generate-pin
 * Generates an 8-character uppercase PIN using UUID
 */
app.post('/generate-pin', (req, res) => {
    try {
        const rawUuid = uuidv4();
        const pin = `NG-${rawUuid.split('-')[0].toUpperCase()}`;

        // Store PIN with metadata
        activePins.push({
            pin: pin,
            hwid: null,      // Assigned on first verification
            createdAt: Date.now(),
            expiresAt: Date.now() + 3600000, // 1 hour validity
            used: false      // New field to prevent multi-use
        });

        console.log(`[PIN] Generated: ${pin}`);
        res.json({
            success: true,
            pin: pin
        });
    } catch (error) {
        console.error("[ERROR] Generation failed:", error);
        res.status(500).json({ success: false, message: "Generation failed" });
    }
});

/**
 * Route: POST /verify-pin
 * Verifies PIN, binds HWID, and marks as used
 */
app.post('/verify-pin', (req, res) => {
    const { pin, hwid } = req.body;
    
    // 1. Search for the PIN in global storage
    const foundPin = activePins.find(p => p.pin === pin);
    
    // 2. Handle NOT FOUND
    if (!foundPin) {
        return res.status(401).json({ 
            success: false, 
            error: "invalid_pin" 
        });
    }

    // 3. Handle EXPIRED
    if (Date.now() > foundPin.expiresAt) {
        return res.status(401).json({ 
            success: false, 
            error: "expired_pin" 
        });
    }

    // 4. Handle ALREADY USED
    if (foundPin.used) {
        return res.status(403).json({ 
            success: false, 
            error: "used_pin" 
        });
    }

    // 5. Handle HWID Binding (Optional security layer)
    if (!foundPin.hwid) {
        foundPin.hwid = hwid;
    } else if (foundPin.hwid !== hwid) {
        return res.status(403).json({ 
            success: false, 
            error: "hwid_mismatch" 
        });
    }

    // 6. Success: Mark as used and return success
    foundPin.used = true;
    
    console.log(`[VERIFY] PIN ${pin} verified for HWID ${hwid}`);
    res.json({ 
        success: true, 
        status: "verified" 
    });
});

// Temporary in-memory storage
let activePins = [];
let scanSessions = []; // Professional session storage
let systemSettings = {
    realTimeScan: true,
    browserMonitoring: true,
    discordMonitoring: true,
    archiveScanning: true,
    telemetry: true,
    autoBan: false
};

/**
 * Route: POST /logs
 * Receives complete scan sessions from C++ client
 */
app.post('/logs', (req, res) => {
    const sessionData = req.body;
    
    // Create professional session object
    const newSession = {
        sessionId: uuidv4().slice(0, 12).toUpperCase(),
        pin: sessionData.pin || 'N/A',
        discordId: sessionData.discordId || 'Unknown',
        discordUsername: sessionData.discordUsername || 'Guest',
        pcName: sessionData.pcName || 'Unknown PC',
        hwid: sessionData.hwid || 'N/A',
        scanTime: new Date(),
        riskLevel: sessionData.riskLevel || 0, // 0 to 100
        detections: sessionData.detections || [],
        browserFindings: sessionData.browserFindings || [],
        discordFindings: sessionData.discordFindings || [],
        suspiciousFiles: sessionData.suspiciousFiles || [],
        suspiciousDlls: sessionData.suspiciousDlls || [],
        suspiciousArchives: sessionData.suspiciousArchives || [],
        registryChanges: sessionData.registryChanges || []
    };

    scanSessions.unshift(newSession);
    if (scanSessions.length > 500) scanSessions.pop();

    console.log(`[SCAN] Session ${newSession.sessionId} received from ${newSession.pcName}. Risk: ${newSession.riskLevel}%`);
    res.json({ success: true, sessionId: newSession.sessionId });
});

/**
 * Route: GET /fetch-logs
 * Returns all sessions for dashboard
 */
app.get('/fetch-logs', (req, res) => {
    res.json({ success: true, logs: scanSessions });
});

/**
 * Route: GET /logs/:id
 * Returns specific session details
 */
app.get('/logs/:id', (req, res) => {
    const session = scanSessions.find(s => s.sessionId === req.params.id);
    if (session) {
        res.json({ success: true, session });
    } else {
        res.status(404).json({ success: false, message: "Session not found" });
    }
});

/**
 * Route: GET /stats
 * Returns system statistics
 */
app.get('/stats', (req, res) => {
    const totalScans = scanSessions.length;
    const flaggedScans = scanSessions.filter(s => s.riskLevel > 50).length;
    const uniqueUsers = new Set(scanSessions.map(s => s.hwid)).size;

    res.json({
        success: true,
        stats: {
            totalScans,
            flaggedScans,
            uniqueUsers,
            activePins: activePins.length,
            uptime: process.uptime()
        }
    });
});

/**
 * Route: GET/POST /settings
 */
app.get('/settings', (req, res) => res.json(systemSettings));
app.post('/settings', (req, res) => {
    systemSettings = { ...systemSettings, ...req.body };
    res.json({ success: true, settings: systemSettings });
});

/**
 * Periodic Cleanup
 * Removes expired pins every 15 minutes to save memory
 */
setInterval(() => {
    const now = Date.now();
    const beforeCount = activePins.length;
    activePins = activePins.filter(p => p.expiresAt > now);
    if (beforeCount !== activePins.length) {
        console.log(`[CLEANUP] Removed ${beforeCount - activePins.length} expired PINs.`);
    }
}, 15 * 60 * 1000);

/**
 * Start the server
 */
app.listen(PORT, () => {
    console.log(`-----------------------------------------`);
    console.log(`NightGuard Backend is running on port ${PORT}`);
    console.log(`Ready for Railway deployment`);
    console.log(`-----------------------------------------`);
});

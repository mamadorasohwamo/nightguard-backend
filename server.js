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

// Temporary in-memory storage for PINs and Logs
let activePins = [];
let scanLogs = [];

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

/**
 * Route: POST /logs
 * Receives scan logs from C++ client or frontend
 */
app.post('/logs', (req, res) => {
    const { pin, type, message, pc_name } = req.body;
    
    const logEntry = {
        id: uuidv4().slice(0, 8),
        pin,
        type: type || 'info',
        message,
        pc_name: pc_name || 'Unknown',
        timestamp: new Date()
    };

    scanLogs.unshift(logEntry); // Newest first
    if (scanLogs.length > 100) scanLogs.pop(); // Keep last 100

    console.log(`[LOG] ${pc_name || 'System'}: ${message}`);
    res.json({ success: true });
});

/**
 * Route: GET /fetch-logs
 * Returns all logs for dashboard
 */
app.get('/fetch-logs', (req, res) => {
    res.json({ success: true, logs: scanLogs });
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

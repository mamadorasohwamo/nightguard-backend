/**
 * NightGuard AC Backend API v5 - Enterprise Grade (In-Memory Edition)
 * Multi-tenant isolation, JWT Auth, Role-based access.
 * NO DATABASE FILE REQUIRED.
 */

const express = require('express');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || 'nightguard_secret_key_2026';

// --- IN-MEMORY STORAGE ---
// Resets on server restart
const storage = {
    customers: [],      // { id, discord_id, username, avatar, role }
    generated_pins: [], // { pin, customer_id, expires_at }
    scans: [],          // { session_id, customer_id, pin_id, player_hwid, player_name, risk_score, verdict, raw_data, created_at }
    detections: []      // { scan_id, category, path, matched_keyword, severity, confidence_score }
};

// Middleware
app.use(cors());
app.use(express.json({ limit: '100mb' }));

// Request Logging Middleware
app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
    next();
});

// Auth Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    console.log(`[AUTH] Received header: ${authHeader}`);

    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        console.log(`[AUTH] Missing token for ${req.url}`);
        return res.status(401).json({ success: false, error: 'Authentication token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.log(`[AUTH] JWT Verification failed: ${err.name} - ${err.message}`);
            const errorMsg = err.name === 'TokenExpiredError' ? 'Token expired' : 'Invalid token';
            return res.status(403).json({ success: false, error: errorMsg });
        }
        
        console.log(`[AUTH] Valid token for user: ${user.username} (${user.role})`);
        req.user = user;
        next();
    });
};

const isAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        console.log(`[AUTH] Admin access denied for user ${req.user.id}`);
        return res.status(403).json({ success: false, error: 'Admin access required' });
    }
    next();
};

// --- API ROUTES ---

app.get('/', (req, res) => res.json({ status: 'online', message: 'NightGuard Enterprise API Online v5 (In-Memory)' }));

// 0. Stats Route
app.get('/api/stats', (req, res) => {
    const totalScans = storage.scans.length;
    const totalUsers = storage.customers.length;
    const criticalDetections = storage.detections.filter(d => d.severity === 'CRITICAL').length;
    const flaggedScans = storage.scans.filter(s => s.risk_score > 50).length;
    const activePins = storage.generated_pins.filter(p => new Date(p.expires_at) > new Date()).length;

    res.json({
        success: true,
        stats: {
            totalScans,
            flaggedScans,
            uniqueUsers: totalUsers,
            activePins,
            criticalDetections,
            onlineUsers: totalUsers // Placeholder
        }
    });
});

// 1. Authentication (Discord OAuth2 placeholder)
app.post('/api/auth/discord', async (req, res) => {
    const { discordId, username, avatar } = req.body;
    
    let user = storage.customers.find(c => c.discord_id === discordId);
    
    if (!user) {
        user = {
            id: storage.customers.length + 1,
            discord_id: discordId,
            username: username,
            avatar: avatar,
            role: (storage.customers.length === 0) ? 'admin' : 'customer' // First user is admin
        };
        storage.customers.push(user);
    }

    const token = jwt.sign({ 
        id: user.id, 
        discordId: user.discord_id, 
        username: user.username, 
        role: user.role 
    }, JWT_SECRET, { expiresIn: '7d' });

    console.log(`[AUTH] Generated 7d token for ${username}`);
    res.json({ token, user: { id: user.id, discordId: user.discord_id, username: user.username, role: user.role } });
});

// 2. PIN System
app.post('/api/pin/generate', authenticateToken, (req, res) => {
    const pin = `NG-${Math.random().toString(36).substring(2, 6).toUpperCase()}-${Math.random().toString(36).substring(2, 6).toUpperCase()}`;
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    const newPin = {
        id: storage.generated_pins.length + 1,
        pin,
        customer_id: req.user.id,
        created_at: new Date().toISOString(),
        expires_at: expiresAt.toISOString()
    };
    
    storage.generated_pins.push(newPin);
    res.json({ success: true, pin, expiresAt });
});

// 3. Scan Upload (from Checker)
app.post('/api/scan/upload', (req, res) => {
    const { pin, hwid, playerName, riskScore, verdict, data } = req.body;

    const pinRow = storage.generated_pins.find(p => p.pin === pin);
    if (!pinRow) return res.status(400).json({ error: 'Invalid PIN' });

    const sessionId = `NG-SESSION-${uuidv4().substring(0, 8).toUpperCase()}`;
    const scanId = storage.scans.length + 1;
    
    const newScan = {
        id: scanId,
        session_id: sessionId,
        customer_id: pinRow.customer_id,
        pin_id: pinRow.id,
        player_hwid: hwid,
        player_name: playerName,
        risk_score: riskScore,
        verdict: verdict,
        raw_data: JSON.stringify(data),
        created_at: new Date().toISOString()
    };
    
    storage.scans.push(newScan);

    // Store detections if any
    if (data.detections && Array.isArray(data.detections)) {
        data.detections.forEach(det => {
            storage.detections.push({
                id: storage.detections.length + 1,
                scan_id: scanId,
                category: det.category,
                path: det.path,
                matched_keyword: det.match,
                severity: det.severity,
                confidence_score: det.confidenceScore || (det.score / 100.0)
            });
        });
    }

    res.json({ success: true, sessionId });
});

// 4. Customer Dashboard (Isolated)
app.get('/api/customer/scans', authenticateToken, (req, res) => {
    const customerScans = storage.scans
        .filter(s => s.customer_id === req.user.id)
        .sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
    res.json(customerScans);
});

// 4.1. Single Scan Details
app.get('/api/scan/:sessionId', authenticateToken, (req, res) => {
    const scan = storage.scans.find(s => s.session_id === req.params.sessionId);
    if (!scan) return res.status(404).json({ success: false, error: 'Scan not found' });
    
    // Authorization: Must be owner or admin
    if (scan.customer_id !== req.user.id && req.user.role !== 'admin') {
        return res.status(403).json({ success: false, error: 'Access denied' });
    }

    const detections = storage.detections.filter(d => d.scan_id === scan.id);
    res.json({ success: true, scan, detections });
});

// 4.2. Delete Scan
app.delete('/api/scan/:sessionId', authenticateToken, (req, res) => {
    const scanIndex = storage.scans.findIndex(s => s.session_id === req.params.sessionId);
    if (scanIndex === -1) return res.status(404).json({ success: false, error: 'Scan not found' });
    
    const scan = storage.scans[scanIndex];
    if (scan.customer_id !== req.user.id && req.user.role !== 'admin') {
        return res.status(403).json({ success: false, error: 'Access denied' });
    }

    storage.scans.splice(scanIndex, 1);
    res.json({ success: true, message: 'Scan deleted' });
});

// 5. Admin Dashboard (Global)
app.get('/api/admin/inspection-logs', authenticateToken, isAdmin, (req, res) => {
    const logs = storage.customers.map(c => {
        const customerScans = storage.scans.filter(s => s.customer_id === c.id);
        const latestScan = customerScans.length > 0 
            ? customerScans.sort((a, b) => new Date(b.created_at) - new Date(a.created_at))[0].created_at 
            : null;

        return {
            id: c.id,
            username: c.username,
            avatar: c.avatar,
            discord_id: c.discord_id,
            total_scans: customerScans.length,
            suspicious_scans: customerScans.filter(s => s.risk_score > 50).length,
            critical_detections: customerScans.filter(s => s.risk_score > 80).length,
            latest_scan_time: latestScan
        };
    });
    res.json(logs);
});

app.get('/api/admin/customer/:id/scans', authenticateToken, isAdmin, (req, res) => {
    const customerId = parseInt(req.params.id);
    const customerScans = storage.scans
        .filter(s => s.customer_id === customerId)
        .sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
    res.json(customerScans);
});

// 6. Access Management
app.get('/api/access/roster', authenticateToken, isAdmin, (req, res) => {
    res.json({ success: true, customers: storage.customers });
});

app.post('/api/access/manage', authenticateToken, isAdmin, (req, res) => {
    const { action, discordId, role } = req.body;
    
    if (action === 'update_role') {
        const user = storage.customers.find(c => c.discord_id === discordId);
        if (user) {
            user.role = role;
            return res.json({ success: true, message: `Role updated to ${role}` });
        }
    }
    
    res.status(400).json({ success: false, error: 'Invalid action or user not found' });
});

// --- ERROR HANDLING ---

// Fallback for unknown API routes
app.use('/api/*', (req, res) => {
    console.log(`[404] Route not found: ${req.method} ${req.url}`);
    res.status(404).json({
        success: false,
        error: 'API route not found'
    });
});

// Global Error Handler
app.use((err, req, res, next) => {
    console.error(`[ERROR] ${err.stack}`);
    res.status(500).json({
        success: false,
        error: 'Internal server error',
        message: err.message
    });
});

app.listen(PORT, () => {
    console.log(`NightGuard Enterprise API (In-Memory) listening on port ${PORT}`);
});

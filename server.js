/**
 * NightGuard AC Backend API v5 - Enterprise Grade
 * Multi-tenant isolation, Database integration, JWT Auth, Role-based access.
 */

const express = require('express');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { db, initDb } = require('./database');

const app = express();
const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || 'nightguard_secret_key_2026';

initDb();

// Middleware
app.use(cors());
app.use(express.json({ limit: '100mb' }));

// Auth Middleware
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

const isAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
    next();
};

// --- API ROUTES ---

app.get('/', (req, res) => res.send('NightGuard Enterprise API Online v5'));

// 1. Authentication (Discord OAuth2 placeholder)
app.post('/api/auth/discord', async (req, res) => {
    const { discordId, username, avatar } = req.body;
    
    // In a real scenario, verify with Discord API
    db.get('SELECT * FROM customers WHERE discord_id = ?', [discordId], (err, user) => {
        if (err) return res.status(500).json({ error: err.message });
        
        if (!user) {
            db.run('INSERT INTO customers (discord_id, username, avatar) VALUES (?, ?, ?)', 
                [discordId, username, avatar], function(err) {
                if (err) return res.status(500).json({ error: err.message });
                const newUser = { id: this.lastID, discordId, username, role: 'customer' };
                const token = jwt.sign(newUser, JWT_SECRET);
                res.json({ token, user: newUser });
            });
        } else {
            const token = jwt.sign({ id: user.id, discordId: user.discord_id, username: user.username, role: user.role }, JWT_SECRET);
            res.json({ token, user: { id: user.id, discordId: user.discord_id, username: user.username, role: user.role } });
        }
    });
});

// 2. PIN System
app.post('/api/pin/generate', authenticateToken, (req, res) => {
    const pin = `NG-${Math.random().toString(36).substring(2, 6).toUpperCase()}-${Math.random().toString(36).substring(2, 6).toUpperCase()}`;
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    db.run('INSERT INTO generated_pins (pin, customer_id, expires_at) VALUES (?, ?, ?)',
        [pin, req.user.id, expiresAt.toISOString()], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, pin, expiresAt });
    });
});

// 3. Scan Upload (from Checker)
app.post('/api/scan/upload', (req, res) => {
    const { pin, hwid, playerName, riskScore, verdict, data } = req.body;

    db.get('SELECT * FROM generated_pins WHERE pin = ?', [pin], (err, pinRow) => {
        if (err || !pinRow) return res.status(400).json({ error: 'Invalid PIN' });

        const sessionId = `NG-SESSION-${uuidv4().substring(0, 8).toUpperCase()}`;
        
        db.run('INSERT INTO scans (session_id, customer_id, pin_id, player_hwid, player_name, risk_score, verdict, raw_data) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            [sessionId, pinRow.customer_id, pinRow.id, hwid, playerName, riskScore, verdict, JSON.stringify(data)],
            function(err) {
                if (err) return res.status(500).json({ error: err.message });
                const scanId = this.lastID;
                
                // Store detections if any
                if (data.detections && Array.isArray(data.detections)) {
                    data.detections.forEach(det => {
                        db.run('INSERT INTO detections (scan_id, category, path, matched_keyword, severity, confidence_score) VALUES (?, ?, ?, ?, ?, ?)',
                            [scanId, det.category, det.path, det.match, det.severity, det.score / 100.0]);
                    });
                }

                res.json({ success: true, sessionId });
            }
        );
    });
});

// 4. Customer Dashboard (Isolated)
app.get('/api/customer/scans', authenticateToken, (req, res) => {
    db.all('SELECT * FROM scans WHERE customer_id = ? ORDER BY created_at DESC', [req.user.id], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// 5. Admin Dashboard (Global)
app.get('/api/admin/inspection-logs', authenticateToken, isAdmin, (req, res) => {
    const query = `
        SELECT c.id, c.username, c.avatar, c.discord_id,
               COUNT(s.id) as total_scans,
               SUM(CASE WHEN s.risk_score > 50 THEN 1 ELSE 0 END) as suspicious_scans,
               SUM(CASE WHEN s.risk_score > 80 THEN 1 ELSE 0 END) as critical_detections,
               MAX(s.created_at) as latest_scan_time
        FROM customers c
        LEFT JOIN scans s ON c.id = s.customer_id
        GROUP BY c.id
    `;
    db.all(query, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.get('/api/admin/customer/:id/scans', authenticateToken, isAdmin, (req, res) => {
    db.all('SELECT * FROM scans WHERE customer_id = ? ORDER BY created_at DESC', [req.params.id], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.listen(PORT, () => {
    console.log(`NightGuard Enterprise API listening on port ${PORT}`);
});

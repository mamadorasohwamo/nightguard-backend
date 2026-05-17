/**
 * NightGuard AC Backend API v5
 * Database authorization (MongoDB), GitHub sync, forensic log isolation.
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const { Octokit } = require('@octokit/rest');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const PORT = process.env.PORT || 8080;

const dbPath = path.join(__dirname, 'access.db');
const db = new sqlite3.Database(dbPath);

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        discordId TEXT PRIMARY KEY,
        role TEXT NOT NULL,
        label TEXT,
        permissions TEXT,
        added_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS scans (
        sessionId TEXT PRIMARY KEY,
        pin TEXT,
        pinOwnerDiscordId TEXT,
        discordId TEXT,
        discordUsername TEXT,
        discordAvatar TEXT,
        pcName TEXT,
        hwid TEXT,
        scanTime DATETIME,
        riskLevel INTEGER,
        status TEXT,
        fullData TEXT
    )`);

    // Add permanent admin
    const adminId = '876582559876796427';
    db.run(`INSERT OR IGNORE INTO users (discordId, role, label, permissions) 
            VALUES (?, 'admin', 'Super Admin', 'full')`, [adminId]);
});

// Helper to wrap DB queries in Promises
const dbRun = (sql, params) => new Promise((resolve, reject) => {
    db.run(sql, params, function(err) {
        if (err) reject(err);
        else resolve(this);
    });
});

const dbAll = (sql, params) => new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
        if (err) reject(err);
        else resolve(rows);
    });
});

// --- Configuration ---
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const GITHUB_OWNER = process.env.GITHUB_REPO_OWNER;
const GITHUB_REPO = process.env.GITHUB_REPO_NAME;

// --- GitHub Octokit Configuration ---
const octokit = new Octokit({ auth: GITHUB_TOKEN });

/** access.json URLs — fallback admins + customers */
const ACCESS_JSON_URL_CANDIDATES = [
    process.env.ACCESS_JSON_URL,
    process.env.ADMIN_JSON_URL,
    'https://nightguardac.vercel.app/access.json',
    'https://nightguardac.vercel.app/admin.json',
    'https://nightguardac.netlify.app/access.json',
].filter(Boolean);

let lastAccessFetchSource = '(none)';

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));

let accessConfig = { admins: [], customers: [] };
const pinOwners = new Map(); // pin string -> creator discord id

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

async function syncAccessToGitHub(newConfig) {
    if (!GITHUB_TOKEN || !GITHUB_OWNER || !GITHUB_REPO) {
        console.error('[github] CRITICAL: Missing configuration! Check GITHUB_TOKEN, GITHUB_REPO_OWNER, GITHUB_REPO_NAME.');
        return false;
    }

    try {
        const filePath = 'access.json'; 
        const newContent = JSON.stringify(newConfig, null, 4);

        console.log(`[github] Syncing access.json to ${GITHUB_OWNER}/${GITHUB_REPO}...`);

        let sha;
        try {
            const { data } = await octokit.repos.getContent({
                owner: GITHUB_OWNER,
                repo: GITHUB_REPO,
                path: filePath
            });
            sha = data.sha;
        } catch (e) {
            if (e.status !== 404) throw e;
        }

        await octokit.repos.createOrUpdateFileContents({
            owner: GITHUB_OWNER,
            repo: GITHUB_REPO,
            path: filePath,
            message: `chore: dashboard update - ${new Date().toISOString()}`,
            content: Buffer.from(newContent).toString('base64'),
            sha
        });

        console.log('[github] Sync successful');
        return true;
    } catch (e) {
        console.error('[github] Sync failed:', e.response?.data || e.message);
        return false;
    }
}

async function fetchAccess() {
    // 1. Load from SQLite (The ONLY Source)
    try {
        const rows = await dbAll("SELECT * FROM users", []);
        accessConfig = {
            admins: rows.filter(r => r.role === 'admin').map(r => ({
                discordId: r.discordId,
                permissions: r.permissions ? r.permissions.split(',') : ['full'],
                label: r.label || 'Admin'
            })),
            customers: rows.filter(r => r.role === 'customer').map(r => ({
                discordId: r.discordId,
                label: r.label || 'Customer'
            }))
        };
        lastAccessFetchSource = 'SQLite DB';
        console.log(`[access] Loaded ${rows.length} users from SQLite`);
        return true;
    } catch (e) {
        console.error('[access] SQLite fetch failed:', e.message);
        return false;
    }
}

function findAdmin(discordId) {
    if (discordId == null || discordId === '') return null;
    const id = String(discordId);
    return (accessConfig.admins || []).find((a) => String(a.discordId) === id) || null;
}

function findCustomer(discordId) {
    if (discordId == null || discordId === '') return null;
    const id = String(discordId);
    return (accessConfig.customers || []).find((c) => String(c.discordId) === id) || null;
}

function hasEnvAdmin(id) {
    return (process.env.ADMIN_DISCORD_IDS || '')
        .split(',')
        .map((s) => s.trim())
        .includes(String(id));
}

function hasEnvCustomer(id) {
    return (process.env.CUSTOMER_DISCORD_IDS || '')
        .split(',')
        .map((s) => s.trim())
        .includes(String(id));
}

function isRegisteredUser(discordId) {
    if (hasEnvAdmin(discordId) || hasEnvCustomer(discordId)) return true;
    return !!findAdmin(discordId) || !!findCustomer(discordId);
}

function isRegisteredAdmin(discordId) {
    return isRegisteredUser(discordId);
}

function isCustomerOnly(discordId) {
    if (hasEnvAdmin(discordId) || findAdmin(discordId)) return false;
    return hasEnvCustomer(discordId) || !!findCustomer(discordId);
}

function hasFullPermission(discordId) {
    if (hasEnvAdmin(discordId)) return true;
    const a = findAdmin(discordId);
    if (!a) return false;
    return (a.permissions || []).includes('full');
}

function canViewSession(viewerId, session) {
    if (hasFullPermission(viewerId)) return true;
    return String(session.pinOwnerDiscordId || '') === String(viewerId || '');
}

function canDeleteSession(viewerId, session) {
    if (hasFullPermission(viewerId)) return true;
    if (!isRegisteredAdmin(viewerId)) return false;
    return String(session.pinOwnerDiscordId || '') === String(viewerId || '');
}

// --- API ROUTES ---

app.get('/', (req, res) => res.send('NightGuard API Online v5 (SQLite Hybrid)'));

// New Endpoint: Force Sync SQLite to GitHub
app.post('/api/access/sync-github', async (req, res) => {
    const viewer = req.headers['x-discord-id'] || req.body?.viewerDiscordId;
    if (!await hasFullPermission(viewer)) {
        return res.status(403).json({ success: false, error: 'forbidden' });
    }

    const ok = await syncAccessToGitHub(accessConfig);
    if (ok) {
        res.json({ success: true, message: 'Successfully synced SQLite database to GitHub' });
    } else {
        res.status(500).json({ success: false, message: 'GitHub sync failed. Check server logs.' });
    }
});

app.get('/api/access/roster', async (req, res) => {
    res.json({ success: true, admins: accessConfig.admins, customers: accessConfig.customers });
});

// 1. PIN SYSTEM
app.post('/api/pin/generate', async (req, res) => {
    try {
        const discordId = req.body?.discordId || req.headers['x-discord-id'];
        let authorized = await isRegisteredUser(discordId);

        if (!authorized && !(accessConfig.admins || []).length && !(accessConfig.customers || []).length) {
            await fetchAccess();
            authorized = await isRegisteredUser(discordId);
        }

        if (!authorized) {
            const knownIds = [
                ...(accessConfig.admins || []).map((a) => String(a.discordId)),
                ...(accessConfig.customers || []).map((c) => String(c.discordId)),
            ];
            return res.status(403).json({
                success: false,
                error: 'forbidden',
                message: 'PIN generation requires an authorized admin or customer account',
                hint:
                    'Add your Discord ID to nightguard-web/public/access.json (admins or customers) ' +
                    'and redeploy Vercel, or set ADMIN_DISCORD_IDS / CUSTOMER_DISCORD_IDS on Railway.',
                yourDiscordId: discordId ? String(discordId) : null,
                adminsLoaded: (accessConfig.admins || []).length,
                customersLoaded: (accessConfig.customers || []).length,
                accessListSource: lastAccessFetchSource,
                registeredIds: knownIds,
            });
        }

        const rawUuid = uuidv4();
        const pin = `NG-${rawUuid.split('-')[0].toUpperCase()}-${Math.floor(1000 + Math.random() * 9000)}`;

        activePins.push({
            pin,
            hwid: null,
            ownerDiscordId: String(discordId),
            createdAt: Date.now(),
            expiresAt: Date.now() + systemSettings.pinExpiryMinutes * 60 * 1000,
            used: false
        });
        pinOwners.set(pin, String(discordId));

        console.log(`[PIN] Generated: ${pin} for admin ${discordId}`);
        res.json({ success: true, pin, ownerDiscordId: String(discordId) });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Generation failed' });
    }
});

app.post('/api/pin/validate', (req, res) => {
    const { pin, hwid } = req.body;
    const foundPin = activePins.find((p) => p.pin === pin);

    if (!foundPin) return res.status(401).json({ success: false, error: 'invalid_pin' });
    if (Date.now() > foundPin.expiresAt) return res.status(401).json({ success: false, error: 'expired_pin' });
    if (foundPin.used) return res.status(403).json({ success: false, error: 'used_pin' });

    if (!foundPin.hwid) {
        foundPin.hwid = hwid;
    } else if (foundPin.hwid !== hwid) {
        return res.status(403).json({ success: false, error: 'hwid_mismatch' });
    }

    foundPin.used = true;
    const owner = foundPin.ownerDiscordId || pinOwners.get(pin);
    if (owner) pinOwners.set(pin, String(owner));

    console.log(`[VERIFY] PIN ${pin} validated for HWID ${hwid} (owner ${owner || 'n/a'})`);
    res.json({ success: true, status: 'verified' });
});

// 2. LOG SYSTEM
app.get('/api/logs', async (req, res) => {
    const viewer = req.query.viewerDiscordId || req.headers['x-discord-id'];
    if (!viewer) return res.status(401).json({ success: false, message: 'Unauthorized' });

    let list = scanSessions;
    const isFullAdmin = await hasFullPermission(viewer);
    const mode = req.query.mode; // 'all' for admin global view

    if (mode === 'all' && isFullAdmin) {
        // Show everything for Admins in Global Mode
        list = scanSessions;
    } else {
        // Default: Only show logs where this user is the owner of the PIN
        // This applies to both Customers AND Admins for their personal history
        list = scanSessions.filter((s) => String(s.pinOwnerDiscordId) === String(viewer));
    }

    // Special case: Admin viewing a specific customer
    const targetCustomer = req.query.targetCustomer;
    if (targetCustomer && isFullAdmin) {
        list = scanSessions.filter((s) => String(s.pinOwnerDiscordId) === String(targetCustomer));
    }
    
    res.json({ success: true, logs: list });
});

app.get('/api/logs/:id', async (req, res) => {
    const viewer = req.query.viewerDiscordId || req.headers['x-discord-id'];
    const session = scanSessions.find((s) => s.sessionId === req.params.id);
    if (!session) {
        return res.status(404).json({ success: false, message: 'Session not found' });
    }
    if (!await canViewSession(viewer, session)) {
        return res.status(403).json({ success: false, message: 'Forbidden' });
    }
    res.json({ success: true, session });
});

app.delete('/api/logs/:id', async (req, res) => {
    const viewer = req.query.viewerDiscordId || req.headers['x-discord-id'];
    const session = scanSessions.find((s) => s.sessionId === req.params.id);
    if (!session) {
        return res.status(404).json({ success: false, message: 'Session not found' });
    }
    if (!await canDeleteSession(viewer, session)) {
        return res.status(403).json({ success: false, message: 'Forbidden' });
    }
    
    try {
        await dbRun("DELETE FROM scans WHERE sessionId = ?", [req.params.id]);
        scanSessions = scanSessions.filter((s) => s.sessionId !== req.params.id);
        console.log(`[DELETE] Session ${req.params.id} removed (by ${viewer}).`);
        res.json({ success: true, message: 'Session deleted' });
    } catch (e) {
        res.status(500).json({ success: false, message: 'Delete failed' });
    }
});

app.post('/api/scan/result', async (req, res) => {
    const data = req.body || {};
    const pin = data.pin || '';
    const ownerFromPin = pinOwners.get(pin) || data.pinOwnerDiscordId || null;

    const newSession = {
        sessionId: uuidv4().slice(0, 12).toUpperCase(),
        pin: pin || 'N/A',
        pinOwnerDiscordId: ownerFromPin || 'unknown',
        discordId: data.discordId || 'N/A',
        discordUsername: data.discordUsername || 'Guest',
        discordAvatar: data.discordAvatar || '',
        pcName: data.pcName || 'Unknown PC',
        hwid: data.hwid || 'N/A',
        scanTime: new Date().toISOString(),
        riskLevel: data.riskLevel || 0,
        detections: data.detections || [],
        browserFindings: data.browserFindings || [],
        discordFindings: data.discordFindings || [],
        discordUserIds: data.discordUserIds || [],
        discordAccountRisk: data.discordAccountRisk || '',
        discordAccounts: data.discordAccounts || [],
        discordAuditReport: data.discordAuditReport || '',
        mtaSerial: data.mtaSerial || '',
        evasionReport: data.evasionReport || '',
        sideLoadEvidence: data.sideLoadEvidence || [],
        advancedForensicReport: data.advancedForensicReport || '',
        dnsCacheHits: data.dnsCacheHits || [],
        explorerMemoryHits: data.explorerMemoryHits || [],
        injectionTraces: data.injectionTraces || [],
        extendedForensicReport: data.extendedForensicReport || '',
        usbForensicHits: data.usbForensicHits || [],
        jumpListHits: data.jumpListHits || [],
        deepForensicReport: data.deepForensicReport || [],
        forensicTimeline: data.forensicTimeline || [],
        unsignedFilesCount: data.unsignedFilesCount || 0,
        highEntropyCount: data.highEntropyCount || 0,
        pcaForensicHits: data.pcaForensicHits || [],
        entropyFindings: data.entropyFindings || [],
        yaraFindings: data.yaraFindings || [],
        unsignedFileFindings: data.unsignedFileFindings || [],
        rpfIntegrityHits: data.rpfIntegrityHits || [],
        suspiciousFiles: data.suspiciousFiles || [],
        suspiciousDlls: data.suspiciousDlls || [],
        suspiciousArchives: data.suspiciousArchives || [],
        registryChanges: data.registryChanges || [],
        status: (data.riskLevel > 50) ? 'FLAGGED' : 'SECURE'
    };

    try {
        await dbRun(`INSERT INTO scans (sessionId, pin, pinOwnerDiscordId, discordId, discordUsername, discordAvatar, pcName, hwid, scanTime, riskLevel, status, fullData) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, 
                     [
                         newSession.sessionId, 
                         newSession.pin, 
                         newSession.pinOwnerDiscordId, 
                         newSession.discordId, 
                         newSession.discordUsername, 
                         newSession.discordAvatar,
                         newSession.pcName, 
                         newSession.hwid, 
                         newSession.scanTime, 
                         newSession.riskLevel, 
                         newSession.status, 
                         JSON.stringify(newSession)
                     ]);
        
        scanSessions.unshift(newSession);
        if (scanSessions.length > 1000) scanSessions.pop();

        console.log(`[SCAN] ${newSession.pcName} risk=${newSession.riskLevel}% owner=${newSession.pinOwnerDiscordId}`);
        res.json({ success: true, sessionId: newSession.sessionId });
    } catch (e) {
        console.error('[scan] Save failed:', e.message);
        res.status(500).json({ success: false, message: 'Failed to save scan result' });
    }
});

// 3. STATS & SETTINGS
app.get('/api/stats', (req, res) => {
    res.json({
        success: true,
        stats: {
            totalScans: scanSessions.length,
            flaggedScans: scanSessions.filter((s) => s.status === 'FLAGGED').length,
            uniqueUsers: new Set(scanSessions.map((s) => s.hwid)).size,
            activePins: activePins.filter((p) => !p.used && p.expiresAt > Date.now()).length,
            uptime: process.uptime()
        }
    });
});

app.get('/api/admin/customer-stats', async (req, res) => {
    const viewer = req.query.viewerDiscordId || req.headers['x-discord-id'];
    if (!await hasFullPermission(viewer)) {
        return res.status(403).json({ success: false, error: 'forbidden', message: 'Admins only' });
    }

    const customerMap = new Map();
    
    // Aggregate data for admins to see who scanned what
    scanSessions.forEach(s => {
        const ownerId = s.pinOwnerDiscordId || 'Unknown';
        if (!customerMap.has(ownerId)) {
            customerMap.set(ownerId, { 
                discordId: ownerId, 
                discordUsername: s.discordUsername || 'Unknown',
                discordAvatar: s.discordAvatar || '',
                totalScans: 0, 
                totalDetections: 0,
                riskScoreSum: 0,
                latestScan: s.scanTime 
            });
        }
        const stats = customerMap.get(ownerId);
        stats.totalScans++;
        stats.totalDetections += (s.detections ? s.detections.length : 0);
        stats.riskScoreSum += (s.riskLevel || 0);
        if (new Date(s.scanTime) > new Date(stats.latestScan)) {
            stats.latestScan = s.scanTime;
            if (s.discordUsername) stats.discordUsername = s.discordUsername;
            if (s.discordAvatar) stats.discordAvatar = s.discordAvatar;
        }
    });

    res.json({ success: true, customers: Array.from(customerMap.values()) });
});

app.get('/api/dashboard/stats', async (req, res) => {
    const viewer = req.query.viewerDiscordId || req.headers['x-discord-id'];
    if (!viewer) return res.status(401).json({ success: false });

    const isFullAdmin = await hasFullPermission(viewer);
    
    // Isolation logic for dashboard counters
    const userScans = isFullAdmin 
        ? scanSessions 
        : scanSessions.filter(s => String(s.pinOwnerDiscordId) === String(viewer));

    const stats = {
        totalScans: userScans.length,
        activePins: activePins.filter(p => isFullAdmin || String(p.ownerDiscordId) === String(viewer)).length,
        detections: userScans.filter(s => s.detections && s.detections.length > 0).length,
        systemStatus: "Healthy"
    };

    res.json({ success: true, stats });
});

app.get('/api/settings', async (req, res) => {
    const viewer = req.query.viewerDiscordId || req.headers['x-discord-id'];
    if (!await hasFullPermission(viewer)) {
        return res.status(403).json({ success: false, error: 'forbidden' });
    }
    res.json(systemSettings);
});

app.post('/api/settings', async (req, res) => {
    const viewer = req.headers['x-discord-id'] || req.body?.viewerDiscordId;
    if (!await hasFullPermission(viewer)) {
        return res.status(403).json({ success: false, error: 'forbidden' });
    }
    const { viewerDiscordId, ...rest } = req.body || {};
    systemSettings = { ...systemSettings, ...rest };
    res.json({ success: true, settings: systemSettings });
});

// 4. Access roster — full admins only (admins + customers lists)
app.get('/api/access/roster', async (req, res) => {
    const viewer = req.query.viewerDiscordId || req.headers['x-discord-id'];
    if (!await hasFullPermission(viewer)) {
        return res.status(403).json({ success: false, error: 'forbidden', message: 'Admins only' });
    }
    res.json({
        success: true,
        admins: accessConfig.admins || [],
        customers: accessConfig.customers || [],
    });
});

/** @deprecated use /api/access/roster */
app.get('/api/admin/admins', async (req, res) => {
    const viewer = req.query.viewerDiscordId || req.headers['x-discord-id'];
    if (!await hasFullPermission(viewer)) {
        return res.status(403).json({ success: false, error: 'forbidden' });
    }
    res.json({ success: true, admins: accessConfig.admins || [] });
});

// 5. Web dashboard — add/remove admin or customer (full permission)
app.post('/api/access/add', async (req, res) => {
    req.body.action = 'add';
    return handleManageAccess(req, res);
});

app.post('/api/access/manage', async (req, res) => {
    return handleManageAccess(req, res);
});

async function handleManageAccess(req, res) {
    const viewer = req.headers['x-discord-id'] || req.body?.viewerDiscordId;
    
    console.log(`[access] Manage request from: ${viewer}`);

    if (!await hasFullPermission(viewer)) {
        return res.status(403).json({ success: false, error: 'forbidden', message: 'Full admin permission required' });
    }

    const { action, discordId, role, permissions, label } = req.body || {};
    if (!discordId || !/^\d{17,20}$/.test(String(discordId))) {
        return res.status(400).json({ success: false, error: 'invalid_discord_id' });
    }
    const targetRole = role === 'customer' ? 'customer' : 'admin';
    const id = String(discordId);

    try {
        // --- DB FIRST STRATEGY ---
        if (action === 'remove') {
            await dbRun("DELETE FROM users WHERE discordId = ?", [id]);
            console.log(`[db] Removed ${id}`);
        } else {
            const permsStr = Array.isArray(permissions) ? permissions.join(',') : 'full';
            const userLabel = label || (targetRole === 'admin' ? 'NightGuard Admin' : 'NightGuard Customer');
            
            await dbRun(`INSERT INTO users (discordId, role, label, permissions) 
                         VALUES (?, ?, ?, ?) 
                         ON CONFLICT(discordId) DO UPDATE SET role=excluded.role, label=excluded.label, permissions=excluded.permissions`, 
                         [id, targetRole, userLabel, permsStr]);
            console.log(`[db] Added/Updated ${id} as ${targetRole}`);
        }

        // Refresh local memory from DB
        await fetchAccess();

        // --- GITHUB SYNC (Background) ---
        // We trigger it but don't block the user if it fails
        syncAccessToGitHub(accessConfig).then(ok => {
            if (ok) console.log('[github] Background sync successful');
            else console.error('[github] Background sync failed (Silent)');
        }).catch(e => console.error('[github] Background sync error:', e.message));

        res.json({ 
            success: true, 
            admins: accessConfig.admins, 
            customers: accessConfig.customers,
            note: 'User updated in local database. GitHub sync started in background.'
        });

    } catch (e) {
        console.error('[access] Manage failed:', e.message);
        res.status(500).json({ success: false, error: 'database_error', message: e.message });
    }
}

/** @deprecated — use /api/access/manage */
app.post('/api/admin/manage', async (req, res) => {
    req.body = { ...(req.body || {}), role: 'admin' };
    return handleManageAccess(req, res);
});

// 6. Bot — rotate access.json
app.post('/api/bot/permission', (req, res) => {
    const secret = process.env.BOT_SECRET || 'change-me-in-production';
    const auth = req.headers.authorization || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
    if (token !== secret) {
        return res.status(401).json({ success: false, error: 'unauthorized' });
    }

    const { action, discordId, permissions } = req.body || {};
    if (!discordId) {
        return res.status(400).json({ success: false, error: 'discordId required' });
    }

    const id = String(discordId);
    let admins = [...(accessConfig.admins || [])];
    let customers = (accessConfig.customers || []).filter((c) => String(c.discordId) !== id);
    const idx = admins.findIndex((a) => String(a.discordId) === id);

    if (action === 'remove') {
        if (idx >= 0) admins.splice(idx, 1);
    } else if (action === 'add' || action === 'give') {
        const perms = Array.isArray(permissions) && permissions.length ? permissions : ['full'];
        if (idx >= 0) admins[idx].permissions = perms;
        else admins.push({ discordId: id, permissions: perms, label: 'Bot Admin' });
    } else {
        return res.status(400).json({ success: false, error: 'action must be add|give|remove' });
    }

    accessConfig.admins = admins;
    accessConfig.customers = customers;

    res.json({
        success: true,
        admins: accessConfig.admins,
        customers: accessConfig.customers,
        note: 'In-memory update. Persist via nightguard-web/public/access.json on Vercel.',
    });
});

setInterval(() => {
    const now = Date.now();
    activePins = activePins.filter((p) => p.expiresAt > now || !p.used);
}, 10 * 60 * 1000);

async function fetchScans() {
    try {
        const rows = await dbAll("SELECT fullData FROM scans ORDER BY scanTime DESC LIMIT 1000", []);
        scanSessions = rows.map(r => JSON.parse(r.fullData));
        console.log(`[scans] Loaded ${scanSessions.length} scans from SQLite`);
        return true;
    } catch (e) {
        console.error('[scans] SQLite fetch failed:', e.message);
        return false;
    }
}

async function boot() {
    await fetchAccess();
    await fetchScans();

    const refreshRaw = process.env.ACCESS_JSON_REFRESH_MS || process.env.ADMIN_JSON_REFRESH_MS;
    const refreshMs = refreshRaw ? parseInt(refreshRaw, 10) : 900000;
    if (!Number.isNaN(refreshMs) && refreshMs >= 60000) {
        setInterval(fetchAccess, refreshMs);
        console.log(
            `[access] Refreshing every ${refreshMs / 1000}s from`,
            ACCESS_JSON_URL_CANDIDATES.join(' | ')
        );
    }

    app.listen(PORT, () => {
        console.log(`=========================================`);
        console.log(`NightGuard AC Backend - Online`);
        console.log(`Port: ${PORT}`);
        console.log(`Access Source: ${lastAccessFetchSource}`);
        console.log(
            `Loaded: ${(accessConfig.admins || []).length} admin(s), ` +
            `${(accessConfig.customers || []).length} customer(s)`
        );
        console.log(`=========================================`);
    });
}

boot().catch((err) => {
    console.error(err);
    process.exit(1);
});

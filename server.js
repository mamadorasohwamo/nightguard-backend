/**
 * NightGuard AC Backend API v5
 * Database authorization (MongoDB), GitHub sync, forensic log isolation.
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const { Octokit } = require('@octokit/rest');

const app = express();
const PORT = process.env.PORT || 8080;

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
        console.warn('[github] Missing credentials for sync. Token:', !!GITHUB_TOKEN, 'Owner:', GITHUB_OWNER, 'Repo:', GITHUB_REPO);
        return false;
    }

    try {
        const filePath = 'public/access.json';
        const newContent = JSON.stringify(newConfig, null, 4);

        console.log(`[github] Attempting to sync access.json to ${GITHUB_OWNER}/${GITHUB_REPO}...`);

        // 1. Get file SHA
        let sha;
        try {
            const { data } = await octokit.repos.getContent({
                owner: GITHUB_OWNER,
                repo: GITHUB_REPO,
                path: filePath
            });
            sha = data.sha;
            console.log('[github] Found existing access.json SHA:', sha);
        } catch (e) {
            if (e.status === 404) {
                console.warn('[github] access.json not found, will create new file');
            } else {
                console.error('[github] Failed to fetch content info:', e.message, 'Status:', e.status);
                throw e; // Rethrow to trigger main catch
            }
        }

        // 2. Update file on GitHub
        const updateResponse = await octokit.repos.createOrUpdateFileContents({
            owner: GITHUB_OWNER,
            repo: GITHUB_REPO,
            path: filePath,
            message: `chore: dynamically updated access.json from admin dashboard at ${new Date().toISOString()}`,
            content: Buffer.from(newContent).toString('base64'),
            sha
        });

        console.log('[github] access.json successfully synced to GitHub. Commit:', updateResponse.data.commit.sha);
        return true;
    } catch (e) {
        console.error('[github] Sync failed CRITICAL:', e.message);
        if (e.status === 401) console.error('[github] ERROR: Invalid GitHub Token (401 Unauthorized)');
        if (e.status === 403) console.error('[github] ERROR: Permission denied or Rate limit (403 Forbidden)');
        if (e.status === 404) console.error('[github] ERROR: Repository or File path not found (404 Not Found)');
        return false;
    }
}

async function fetchAccess() {
    // 1. Try Loading from ENV (Primary Fallback)
    const envAdmins = (process.env.ADMIN_DISCORD_IDS || '')
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
    const envCustomers = (process.env.CUSTOMER_DISCORD_IDS || '')
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);

    if (envAdmins.length || envCustomers.length) {
        accessConfig = {
            admins: envAdmins.map((discordId) => ({
                discordId: String(discordId),
                permissions: ['full'],
                label: 'ENV ADMIN',
            })),
            customers: envCustomers.map((discordId) => ({
                discordId: String(discordId),
                label: 'ENV Customer',
            })),
        };
        lastAccessFetchSource = 'ENV ids';
        console.log('[access] Loaded from ENV');
        return true;
    }

    // 2. Try Loading from External access.json URLs (GitHub/Vercel)
    for (const url of ACCESS_JSON_URL_CANDIDATES) {
        try {
            const res = await fetch(url, { cache: 'no-store' });
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data = await res.json();
            if (!data || typeof data !== 'object' || !Array.isArray(data.admins)) {
                throw new Error('invalid access.json shape');
            }
            accessConfig = {
                admins: data.admins || [],
                customers: Array.isArray(data.customers) ? data.customers : [],
            };
            lastAccessFetchSource = url;
            console.log('[access] Loaded from', url);
            return true;
        } catch (e) {
            console.warn('[access] Failed to fetch', url, '—', e.message || e);
        }
    }

    accessConfig = { admins: [], customers: [] };
    return false;
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

app.get('/', (req, res) => res.send('NightGuard API Online v4'));

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
    let list = scanSessions;
    if (!await hasFullPermission(viewer)) {
        list = scanSessions.filter((s) => (s.pinOwnerDiscordId === String(viewer)));
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
    scanSessions = scanSessions.filter((s) => s.sessionId !== req.params.id);
    console.log(`[DELETE] Session ${req.params.id} removed (by ${viewer}).`);
    res.json({ success: true, message: 'Session deleted' });
});

app.post('/api/scan/result', (req, res) => {
    const data = req.body || {};
    const pin = data.pin || '';
    const ownerFromPin = pinOwners.get(pin) || data.pinOwnerDiscordId || null;

    const newSession = {
        sessionId: uuidv4().slice(0, 12).toUpperCase(),
        pin: pin || 'N/A',
        pinOwnerDiscordId: ownerFromPin || 'unknown',
        discordId: data.discordId || 'N/A',
        discordUsername: data.discordUsername || 'Guest',
        pcName: data.pcName || 'Unknown PC',
        hwid: data.hwid || 'N/A',
        scanTime: new Date(),
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

    scanSessions.unshift(newSession);
    if (scanSessions.length > 1000) scanSessions.pop();

    console.log(
        `[SCAN] ${newSession.pcName} risk=${newSession.riskLevel}% owner=${newSession.pinOwnerDiscordId}`
    );
    res.json({ success: true, sessionId: newSession.sessionId });
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

// 4. ADMIN INSPECTION LOGS - CUSTOMER OVERVIEW
app.get('/api/admin/customer-stats', async (req, res) => {
    const viewer = req.query.viewerDiscordId || req.headers['x-discord-id'];
    if (!await hasFullPermission(viewer)) {
        return res.status(403).json({ success: false, error: 'forbidden', message: 'Admins only' });
    }

    const customerMap = new Map();

    // Group scans by owner
    scanSessions.forEach(session => {
        const ownerId = session.pinOwnerDiscordId || 'unknown';
        if (!customerMap.has(ownerId)) {
            customerMap.set(ownerId, {
                discordId: ownerId,
                totalScans: 0,
                totalDetections: 0,
                latestScan: null,
                riskScoreSum: 0
            });
        }
        const data = customerMap.get(ownerId);
        data.totalScans++;
        data.totalDetections += (session.detections?.length || 0);
        
        const scanDate = new Date(session.scanTime);
        if (!data.latestScan || scanDate > new Date(data.latestScan)) {
            data.latestScan = session.scanTime;
        }
        data.riskScoreSum += (session.riskLevel || 0);
    });

    const result = Array.from(customerMap.values());
    res.json({ success: true, customers: result });
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
    if (!hasFullPermission(viewer)) {
        return res.status(403).json({ success: false, error: 'forbidden', message: 'Full admin permission required' });
    }

    const { action, discordId, role, permissions, label } = req.body || {};
    if (!discordId || !/^\d{17,20}$/.test(String(discordId))) {
        return res.status(400).json({ success: false, error: 'invalid_discord_id' });
    }
    const listRole = role === 'customer' ? 'customer' : 'admin';
    const id = String(discordId);

    // Current config
    let admins = [...(accessConfig.admins || [])];
    let customers = [...(accessConfig.customers || [])];

    const removeFromBoth = () => {
        admins = admins.filter(a => String(a.discordId) !== id);
        customers = customers.filter(c => String(c.discordId) !== id);
    };

    try {
        if (action === 'remove') {
            removeFromBoth();
        } else if (action === 'add' || action === 'give') {
            removeFromBoth();
            if (listRole === 'customer') {
                customers.push({
                    discordId: id,
                    label: label || 'NightGuard Customer',
                });
            } else {
                const perms = Array.isArray(permissions) && permissions.length ? permissions : ['full'];
                admins.push({
                    discordId: id,
                    permissions: perms,
                    label: label || 'NightGuard Admin',
                });
            }
        } else {
            return res.status(400).json({ success: false, error: 'action must be add or remove' });
        }

        const newConfig = { admins, customers };

        // SYNC TO GITHUB
        const syncOk = await syncAccessToGitHub(newConfig);
        if (!syncOk) {
            return res.status(500).json({ success: false, error: 'github_sync_failed' });
        }

        // Update local memory only after successful GitHub sync
        accessConfig = newConfig;

        res.json({
            success: true,
            admins: accessConfig.admins,
            customers: accessConfig.customers,
            note: 'Successfully updated access.json on GitHub.',
        });
    } catch (e) {
        console.error('[access] Manage failed:', e.message);
        res.status(500).json({ success: false, error: 'internal_error', message: e.message });
    }
}

/** @deprecated — adds to admins list only */
app.post('/api/admin/manage', async (req, res) => {
    req.body = { ...(req.body || {}), role: 'admin' };
    const viewer = req.headers['x-discord-id'] || req.body?.viewerDiscordId;
    if (!await hasFullPermission(viewer)) {
        return res.status(403).json({ success: false, error: 'forbidden' });
    }
    const { action, discordId, permissions, label } = req.body || {};
    if (!discordId) return res.status(400).json({ success: false, error: 'discordId required' });
    const id = String(discordId);
    let admins = [...(accessConfig.admins || [])];
    let customers = (accessConfig.customers || []).filter((c) => String(c.discordId) !== id);
    const idx = admins.findIndex((a) => String(a.discordId) === id);
    if (action === 'remove') {
        if (idx >= 0) admins.splice(idx, 1);
    } else if (action === 'add' || action === 'give') {
        const perms = Array.isArray(permissions) && permissions.length ? permissions : ['full'];
        const entry = { discordId: id, permissions: perms, label: label || 'NightGuard Admin' };
        if (idx >= 0) admins[idx] = { ...admins[idx], ...entry };
        else admins.push(entry);
    } else {
        return res.status(400).json({ success: false, error: 'action must be add or remove' });
    }
    accessConfig.admins = admins;
    accessConfig.customers = customers;
    res.json({
        success: true,
        admins: accessConfig.admins,
        customers: accessConfig.customers,
        note: 'Applied in-memory. Commit access.json and redeploy Vercel.',
    });
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

async function boot() {
    await fetchAccess();

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

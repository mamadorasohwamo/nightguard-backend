/**
 * NightGuard AC Backend API v4
 * Forensic log isolation, admin.json permissions, PIN ownership.
 */

const express = require('express');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 8080;

/** Admin list URLs — first success wins (must match deployed nightguard-web /admin.json) */
const ADMIN_JSON_URL_CANDIDATES = [
    process.env.ADMIN_JSON_URL,
    'https://nightguardac.vercel.app/admin.json',
    'https://nightguardac.netlify.app/admin.json',
].filter(Boolean);

let lastAdminFetchSource = '(none)';

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));

let adminConfig = { admins: [] };
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

async function fetchAdmins() {
    const envIds = (process.env.ADMIN_DISCORD_IDS || '')
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);

    if (envIds.length) {
        const fromEnv = envIds.map((discordId) => ({
            discordId: String(discordId),
            permissions: ['full'],
            label: 'ENV ADMIN_DISCORD_IDS',
        }));
        adminConfig = { admins: fromEnv };
        lastAdminFetchSource = 'ADMIN_DISCORD_IDS env';
        console.log('[admin] Loaded', fromEnv.length, 'admin(s) from ADMIN_DISCORD_IDS');
        return true;
    }

    for (const url of ADMIN_JSON_URL_CANDIDATES) {
        try {
            const res = await fetch(url, { cache: 'no-store' });
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data = await res.json();
            if (!data || typeof data !== 'object' || !Array.isArray(data.admins)) {
                throw new Error('invalid admin.json shape');
            }
            adminConfig = data;
            lastAdminFetchSource = url;
            console.log(
                '[admin] Loaded admin.json —',
                adminConfig.admins.length,
                'entries from',
                url
            );
            return true;
        } catch (e) {
            console.warn('[admin] Failed to fetch', url, '—', e.message || e);
        }
    }

    if (!(adminConfig.admins || []).length) {
        adminConfig = { admins: [] };
        console.error(
            '[admin] CRITICAL: No admins loaded. PIN generation will fail. ' +
            'Deploy admin.json to Vercel or set ADMIN_JSON_URL / ADMIN_DISCORD_IDS on Railway.'
        );
    }
    return (adminConfig.admins || []).length > 0;
}

function findAdmin(discordId) {
    if (discordId == null || discordId === '') return null;
    const id = String(discordId);
    return (adminConfig.admins || []).find((a) => String(a.discordId) === id) || null;
}

function hasEnvAdmin(id) {
    const extra = (process.env.ADMIN_DISCORD_IDS || '')
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
    return extra.includes(String(id));
}

/** Any permission listed in admin.json (generate PIN, see own logs) */
function isRegisteredAdmin(discordId) {
    return hasEnvAdmin(discordId) || !!findAdmin(discordId);
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
        let authorized = isRegisteredAdmin(discordId);

        if (!authorized && !(adminConfig.admins || []).length) {
            await fetchAdmins();
            authorized = isRegisteredAdmin(discordId);
        }

        if (!authorized) {
            const knownIds = (adminConfig.admins || []).map((a) => String(a.discordId));
            return res.status(403).json({
                success: false,
                error: 'forbidden',
                message: 'PIN generation requires an authorized admin account',
                hint:
                    'Backend admin list is loaded from your deployed admin.json. ' +
                    'Ensure your Discord ID is in nightguard-web/public/admin.json on Vercel, ' +
                    'or set ADMIN_DISCORD_IDS on Railway.',
                yourDiscordId: discordId ? String(discordId) : null,
                adminsLoaded: knownIds.length,
                adminListSource: lastAdminFetchSource,
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
app.get('/api/logs', (req, res) => {
    const viewer = req.query.viewerDiscordId || req.headers['x-discord-id'];
    let list = scanSessions;
    if (!hasFullPermission(viewer)) {
        list = scanSessions.filter((s) => canViewSession(viewer, s));
    }
    res.json({ success: true, logs: list });
});

app.get('/api/logs/:id', (req, res) => {
    const viewer = req.query.viewerDiscordId || req.headers['x-discord-id'];
    const session = scanSessions.find((s) => s.sessionId === req.params.id);
    if (!session) {
        return res.status(404).json({ success: false, message: 'Session not found' });
    }
    if (!canViewSession(viewer, session)) {
        return res.status(403).json({ success: false, message: 'Forbidden' });
    }
    res.json({ success: true, session });
});

app.delete('/api/logs/:id', (req, res) => {
    const viewer = req.query.viewerDiscordId || req.headers['x-discord-id'];
    const session = scanSessions.find((s) => s.sessionId === req.params.id);
    if (!session) {
        return res.status(404).json({ success: false, message: 'Session not found' });
    }
    if (!canDeleteSession(viewer, session)) {
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

app.get('/api/settings', (req, res) => {
    const viewer = req.query.viewerDiscordId || req.headers['x-discord-id'];
    if (!hasFullPermission(viewer)) {
        return res.status(403).json({ success: false, error: 'forbidden' });
    }
    res.json(systemSettings);
});

app.post('/api/settings', (req, res) => {
    const viewer = req.headers['x-discord-id'] || req.body?.viewerDiscordId;
    if (!hasFullPermission(viewer)) {
        return res.status(403).json({ success: false, error: 'forbidden' });
    }
    const { viewerDiscordId, ...rest } = req.body || {};
    systemSettings = { ...systemSettings, ...rest };
    res.json({ success: true, settings: systemSettings });
});

// 4. Admin list — any registered admin (from public admin.json) may view; full perm still for settings
app.get('/api/admin/admins', (req, res) => {
    const viewer = req.query.viewerDiscordId || req.headers['x-discord-id'];
    if (!isRegisteredAdmin(viewer)) {
        return res.status(403).json({ success: false, error: 'forbidden' });
    }
    res.json({ success: true, admins: adminConfig.admins || [] });
});

// 5. Bot — rotate admin.json
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
    const admins = adminConfig.admins || [];
    const idx = admins.findIndex((a) => String(a.discordId) === id);

    if (action === 'remove') {
        if (idx >= 0) admins.splice(idx, 1);
    } else if (action === 'add' || action === 'give') {
        const perms = Array.isArray(permissions) && permissions.length
            ? permissions
            : ['full'];
        if (idx >= 0) admins[idx].permissions = perms;
        else admins.push({ discordId: id, permissions: perms });
    } else {
        return res.status(400).json({ success: false, error: 'action must be add|give|remove' });
    }

    adminConfig.admins = admins;

    res.json({
        success: true,
        admins: adminConfig.admins,
        note:
            'In-memory update applied. To persist and survive backend restarts, edit nightguard-web/public/admin.json, deploy your static site, and wait for the next refresh (or set ADMIN_JSON_REFRESH_MS).'
    });
});

setInterval(() => {
    const now = Date.now();
    activePins = activePins.filter((p) => p.expiresAt > now || !p.used);
}, 10 * 60 * 1000);

async function boot() {
    await fetchAdmins();

    const refreshRaw = process.env.ADMIN_JSON_REFRESH_MS;
    const refreshMs = refreshRaw ? parseInt(refreshRaw, 10) : 900000;
    if (!Number.isNaN(refreshMs) && refreshMs >= 60000) {
        setInterval(fetchAdmins, refreshMs);
        console.log(
            `[admin] Refreshing admin list every ${refreshMs / 1000}s from`,
            ADMIN_JSON_URL_CANDIDATES.join(' | ')
        );
    }

    app.listen(PORT, () => {
        console.log(`=========================================`);
        console.log(`NightGuard AC Backend v4 - Online`);
        console.log(`Port: ${PORT}`);
        console.log(`Admin list URLs: ${ADMIN_JSON_URL_CANDIDATES.join(' -> ')}`);
        console.log(`Admins loaded: ${(adminConfig.admins || []).length} (${lastAdminFetchSource})`);
        console.log(`=========================================`);
    });
}

boot().catch((err) => {
    console.error(err);
    process.exit(1);
});

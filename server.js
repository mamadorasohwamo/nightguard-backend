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

// Temporary in-memory storage for PINs
// Note: In production, consider using Redis or MongoDB for persistence
let activePins = [];

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
        // Generate UUID and take first 8 characters
        const rawUuid = uuidv4();
        const pin = rawUuid.split('-')[0].toUpperCase();

        // Store PIN in memory
        activePins.push({
            pin: pin,
            createdAt: new Date(),
            expiresAt: new Date(Date.now() + 10 * 60 * 1000) // Expires in 10 minutes
        });

        console.log(`[PIN] Generated: ${pin}`);

        res.json({
            success: true,
            pin: pin
        });
    } catch (error) {
        console.error("[ERROR] Pin Generation failed:", error);
        res.status(500).json({
            success: false,
            message: "Internal Server Error"
        });
    }
});

/**
 * Start the server
 */
app.listen(PORT, () => {
    console.log(`-----------------------------------------`);
    console.log(`NightGuard Backend is running on port ${PORT}`);
    console.log(`Ready for Railway deployment`);
    console.log(`-----------------------------------------`);
});

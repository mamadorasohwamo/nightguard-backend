# NightGuard AC Backend

A lightweight Node.js + Express backend for the NightGuard Anti-Cheat system.

## Setup Instructions

1. **Install Dependencies**
   ```bash
   npm install
   ```

2. **Run the Server**
   ```bash
   npm start
   ```

## API Endpoints

- `GET /`: Health check, returns "NightGuard API Online".
- `POST /generate-pin`: Generates a unique 8-character uppercase PIN.

## Deployment

This project is ready for deployment on **Railway** or any other Node.js hosting platform. It uses the `PORT` environment variable and is configured with the standard `npm start` script.

## Features

- **CORS Enabled**: Ready for frontend cross-origin requests.
- **PIN Generation**: Uses `uuid` for secure, unique identifiers.
- **In-Memory Storage**: Temporarily stores pins for verification.

# NightGuard AC Backend (v5)

A lightweight Node.js + Express backend for the NightGuard Anti-Cheat system, now featuring Database Authorization and GitHub Sync.

## Setup Instructions

1. **Install Dependencies**
   ```bash
   npm install
   ```

2. **Environment Variables**
   Create a `.env` file in the root directory (see `env_example.txt`):
   - `PORT`: Server port (default: 8080)
   - `MONGODB_URI`: Your MongoDB connection string.
   - `GITHUB_TOKEN`: Personal Access Token with repository write permissions.
   - `GITHUB_REPO_OWNER`: Your GitHub username.
   - `GITHUB_REPO_NAME`: The repository name (e.g., `nightguard-web`).
   - `ADMIN_DISCORD_IDS`: Comma-separated list of fallback admin Discord IDs.

3. **Run the Server**
   ```bash
   npm start
   ```

## Features

- **Database Authorization**: Uses MongoDB to store and manage authorized admins and customers.
- **GitHub Sync**: Automatically commits and pushes updates to `public/access.json` in the web repository for redundancy and history.
- **PIN System**: Secure PIN generation and validation for client-side scanning.
- **Forensic Logs**: Securely stores and isolates forensic scan results.
- **Discord OAuth2 Integration**: Verifies user roles against the database.


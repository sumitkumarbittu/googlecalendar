#Production-ready Node.js server for Google Sign-in and Calendar integration.

## Features

- ✅ Google OAuth 2.0 authentication
- ✅ Google Calendar read/write access
- ✅ Session management with secure cookies
- ✅ Auto-detection for Render.com, local, and production environments
- ✅ CORS configured for cross-origin requests
- ✅ Graceful shutdown handling

## API Endpoints

### Authentication
- `GET /api/auth/google` - Initiate Google OAuth flow
- `GET /api/auth/google/callback` - OAuth callback handler
- `GET /api/auth/status` - Check authentication status
- `POST /api/auth/logout` - Logout and clear session
- `GET /api/auth/config` - Get OAuth configuration

### Calendar
- `GET /api/calendar/current` - Get current meeting
- `GET /api/calendar/today` - Get today's meetings
- `POST /api/calendar/events` - Create or update calendar event

### Health & Info
- `GET /api/health` - Health check
- `GET /api/info` - Server info
- `GET /api/debug` - Debug info (dev/Render only)

## Deployment on Render.com

1. **Create a new Web Service** on Render.com
2. **Connect your repository**
3. **Set the following:**
   - **Root Directory:** `public`
   - **Build Command:** `npm install`
   - **Start Command:** `npm start`

4. **Add Environment Variables:**
   ```
   GOOGLE_CLIENT_ID=your_client_id
   GOOGLE_CLIENT_SECRET=your_client_secret
   SESSION_SECRET=your_random_secret
   ```

5. **Configure Google Cloud Console:**
   - Go to [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
   - Add to **Authorized Redirect URIs:**
     ```
     https://your-app.onrender.com/api/auth/google/callback
     ```
   - Add to **Authorized JavaScript Origins:**
     ```
     https://your-app.onrender.com
     ```

## Local Development

1. **Install dependencies:**
   ```bash
   cd public
   npm install
   ```

2. **Create `.env` file:**
   ```env
   GOOGLE_CLIENT_ID=your_client_id
   GOOGLE_CLIENT_SECRET=your_client_secret
   FRONTEND_URL=http://localhost:3000
   PORT=10000
   NODE_ENV=development
   ```

3. **Run the server:**
   ```bash
   npm run dev
   ```

4. **Configure Google Cloud Console for local:**
   - Add `http://localhost:10000/api/auth/google/callback` to Redirect URIs
   - Add `http://localhost:10000` and `http://localhost:3000` to JavaScript Origins

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `GOOGLE_CLIENT_ID` | Yes | Google OAuth Client ID |
| `GOOGLE_CLIENT_SECRET` | Yes | Google OAuth Client Secret |
| `PORT` | No | Server port (default: 10000) |
| `NODE_ENV` | No | Environment mode |
| `FRONTEND_URL` | Auto | Frontend URL (auto-detected on Render) |
| `REDIRECT_URI` | Auto | OAuth redirect URI (auto-generated) |
| `SESSION_SECRET` | No | Session encryption key (auto-generated if not set) |

## Session Security

- Sessions are stored in-memory (lost on server restart)
- Session timeout: 1 hour
- Automatic cleanup every 5 minutes
- Secure cookies enabled in production
- SameSite cookie policy based on environment

## Client Integration

The frontend can use either:

1. **Client-side OAuth** (using Google Identity Services) - No server required
2. **Server-side OAuth** (using this server) - More secure, supports refresh tokens

For server-side integration, make requests to the API endpoints:

```javascript
// Initiate login
const response = await fetch('/api/auth/google');
const { authUrl } = await response.json();
window.location.href = authUrl;

// Check status
const status = await fetch('/api/auth/status', { credentials: 'include' });
const { authenticated, user } = await status.json();

// Create calendar event
await fetch('/api/calendar/events', {
  method: 'POST',
  credentials: 'include',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    summary: 'Meeting from Transcription',
    description: 'Transcribed notes...',
    start: { dateTime: '2024-01-15T10:00:00Z' },
    end: { dateTime: '2024-01-15T11:00:00Z' }
  })
});
```

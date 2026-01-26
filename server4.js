require('dotenv').config();
const express = require('express');
const session = require('express-session');
const { google } = require('googleapis');
const crypto = require('crypto');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const morgan = require('morgan');

const app = express();

// ==================== CONFIGURATION ====================
const PORT = process.env.PORT || 10000;
const NODE_ENV = process.env.NODE_ENV || 'development';

// Detect environment
const isLocal = NODE_ENV === 'development';
const isRender = process.env.RENDER === 'true' || 
                 process.env.RENDER_EXTERNAL_URL !== undefined;

console.log(`Environment: ${isRender ? 'Render.com' : isLocal ? 'Local' : 'Production'}`);
console.log(`RENDER_EXTERNAL_URL: ${process.env.RENDER_EXTERNAL_URL || 'Not set'}`);

// Set URLs based on environment
let FRONTEND_URL, REDIRECT_URI;

if (isRender && process.env.RENDER_EXTERNAL_URL) {
  // Running on Render.com
  FRONTEND_URL = process.env.RENDER_EXTERNAL_URL;
  REDIRECT_URI = `${FRONTEND_URL}/api/auth/google/callback`;
  console.log(`Using Render URL: ${FRONTEND_URL}`);
} else if (isLocal) {
  // Local development
  FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';
  REDIRECT_URI = process.env.REDIRECT_URI || `http://localhost:${PORT}/api/auth/google/callback`;
  console.log(`Using Local URL: ${FRONTEND_URL}`);
} else {
  // Other production environment
  FRONTEND_URL = process.env.FRONTEND_URL;
  REDIRECT_URI = process.env.REDIRECT_URI || `${FRONTEND_URL}/api/auth/google/callback`;
}

// Override with environment variables if explicitly set
if (process.env.FRONTEND_URL) FRONTEND_URL = process.env.FRONTEND_URL;
if (process.env.REDIRECT_URI) REDIRECT_URI = process.env.REDIRECT_URI;

// Final validation
if (!FRONTEND_URL || !REDIRECT_URI) {
  console.error('❌ ERROR: FRONTEND_URL and REDIRECT_URI must be set');
  process.exit(1);
}

// Google OAuth Configuration
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;

// Validate required environment variables
if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
  console.error('❌ ERROR: GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET are required in .env file');
  console.error('Please set them in Render.com environment variables');
  process.exit(1);
}

console.log(`✅ Configuration loaded:`);
console.log(`   Frontend URL: ${FRONTEND_URL}`);
console.log(`   Redirect URI: ${REDIRECT_URI}`);
console.log(`   Port: ${PORT}`);
console.log(`   Google Client ID: ${GOOGLE_CLIENT_ID ? 'Set' : 'Missing!'}`);

// ==================== MIDDLEWARE ====================

// CORS - Allow from anywhere with credentials
app.use(cors({
  origin: function(origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    // Allow all origins in development and Render
    if (!isLocal) return callback(null, true);
    
    // In local development, allow common origins
    const allowedOrigins = [
      'http://localhost:3000',
      'http://localhost:3001',
      'http://localhost:10000',
      FRONTEND_URL
    ];
    
    if (allowedOrigins.includes(origin) || origin.includes('localhost')) {
      return callback(null, true);
    }
    
    return callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin', 'Cookies'],
  exposedHeaders: ['Set-Cookie']
}));

// Handle preflight requests
app.options('*', cors());

// Request logging
app.use(morgan(isLocal ? 'dev' : 'combined'));

// Body parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Cookies and sessions
app.use(cookieParser());

// Session configuration
const sessionConfig = {
  name: 'calendar_session',
  secret: process.env.SESSION_SECRET || crypto.randomBytes(64).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    maxAge: 60 * 60 * 1000, // 1 hour
    path: '/'
  },
  store: new session.MemoryStore()
};

// Adjust cookie settings based on environment
if (isRender) {
  // Render requires secure cookies and sameSite none for cross-site
  sessionConfig.cookie.secure = true;
  sessionConfig.cookie.sameSite = 'none';
  console.log('🔒 Using secure cookies for Render.com');
} else if (isLocal) {
  // Local development
  sessionConfig.cookie.secure = false;
  sessionConfig.cookie.sameSite = 'lax';
} else {
  // Other production
  sessionConfig.cookie.secure = true;
  sessionConfig.cookie.sameSite = 'strict';
}

app.use(session(sessionConfig));

// Security headers
app.use((req, res, next) => {
  // Remove unnecessary headers
  res.removeHeader('X-Powered-By');
  
  // Add security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  
  if (isRender || !isLocal) {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  
  next();
});

// ==================== IN-MEMORY STORAGE ====================
const activeSessions = new Map(); // sessionId → {tokens, userInfo, expiry}
const transcriptionSessions = new Map(); // sessionId → {transcription data}
const CLEANUP_INTERVAL = 5 * 60 * 1000; // 5 minutes

// ==================== GOOGLE OAUTH CLIENT ====================
const oauth2Client = new google.auth.OAuth2(
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  REDIRECT_URI
);

// ==================== UTILITY FUNCTIONS ====================

/**
 * Generate a secure random session ID
 */
function generateSessionId() {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Get authenticated calendar client for a session
 */
function getCalendarClient(sessionId) {
  const sessionData = activeSessions.get(sessionId);
  
  if (!sessionData) {
    throw new Error('Session not found or expired');
  }
  
  if (sessionData.expiry < Date.now()) {
    activeSessions.delete(sessionId);
    throw new Error('Session expired');
  }
  
  const client = new google.auth.OAuth2(
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET
  );
  
  client.setCredentials({
    access_token: sessionData.tokens.access_token,
    refresh_token: sessionData.tokens.refresh_token
  });
  
  return {
    client,
    calendar: google.calendar({ version: 'v3', auth: client }),
    userInfo: sessionData.userInfo
  };
}

/**
 * Refresh access token if expired
 */
async function refreshAccessToken(sessionId) {
  const sessionData = activeSessions.get(sessionId);
  
  if (!sessionData || !sessionData.tokens.refresh_token) {
    return false;
  }
  
  try {
    const client = new google.auth.OAuth2(
      GOOGLE_CLIENT_ID,
      GOOGLE_CLIENT_SECRET
    );
    
    client.setCredentials({
      refresh_token: sessionData.tokens.refresh_token
    });
    
    const { credentials } = await client.refreshAccessToken();
    
    // Update session with new tokens
    sessionData.tokens.access_token = credentials.access_token;
    sessionData.tokens.expiry_date = credentials.expiry_date;
    sessionData.expiry = credentials.expiry_date || (Date.now() + 3500 * 1000); // ~1 hour
    
    activeSessions.set(sessionId, sessionData);
    return true;
  } catch (error) {
    console.error('Token refresh failed:', error.message);
    activeSessions.delete(sessionId);
    return false;
  }
}

/**
 * Clean up expired sessions
 */
function cleanupExpiredSessions() {
  const now = Date.now();
  let cleaned = 0;
  
  for (const [sessionId, sessionData] of activeSessions.entries()) {
    if (sessionData.expiry < now) {
      activeSessions.delete(sessionId);
      transcriptionSessions.delete(sessionId);
      cleaned++;
    }
  }
  
  // Clean up old transcription sessions without active OAuth
  for (const [sessionId] of transcriptionSessions.entries()) {
    if (!activeSessions.has(sessionId)) {
      transcriptionSessions.delete(sessionId);
    }
  }
  
  if (cleaned > 0 && isLocal) {
    console.log(`[Cleanup] Removed ${cleaned} expired sessions`);
  }
}

/**
 * Validate session from request
 */
async function validateSession(req) {
  const sessionId = req.cookies.session_id || req.session?.sessionId;
  
  if (!sessionId || !activeSessions.has(sessionId)) {
    return { valid: false, error: 'Session not found' };
  }
  
  const sessionData = activeSessions.get(sessionId);
  
  // Check if session expired
  if (sessionData.expiry < Date.now()) {
    // Try to refresh token
    const refreshed = await refreshAccessToken(sessionId);
    if (!refreshed) {
      return { valid: false, error: 'Session expired' };
    }
  }
  
  return { 
    valid: true, 
    sessionId, 
    sessionData,
    userInfo: sessionData.userInfo
  };
}

/**
 * Get current meeting from events
 */
function getCurrentMeeting(events) {
  if (!events || events.length === 0) return null;
  
  const now = new Date();
  
  return events.find(event => {
    try {
      const start = new Date(event.start.dateTime || event.start.date);
      const end = new Date(event.end.dateTime || event.end.date);
      return start <= now && now <= end;
    } catch (error) {
      return false;
    }
  }) || null;
}

/**
 * Get upcoming meetings (next 24 hours)
 */
function getUpcomingMeetings(events) {
  if (!events || events.length === 0) return [];
  
  const now = new Date();
  const tomorrow = new Date(now.getTime() + 24 * 60 * 60 * 1000);
  
  return events
    .filter(event => {
      try {
        const start = new Date(event.start.dateTime || event.start.date);
        return start > now && start < tomorrow;
      } catch (error) {
        return false;
      }
    })
    .sort((a, b) => {
      const aStart = new Date(a.start.dateTime || a.start.date);
      const bStart = new Date(b.start.dateTime || b.start.date);
      return aStart - bStart;
    });
}

// ==================== AUTHENTICATION ENDPOINTS ====================

/**
 * 1. Initiate Google OAuth flow
 */
app.get('/api/auth/google', (req, res) => {
  try {
    const sessionId = generateSessionId();
    
    // Store session in memory
    activeSessions.set(sessionId, {
      tokens: null,
      userInfo: null,
      expiry: Date.now() + (60 * 60 * 1000) // 1 hour
    });
    
    // Store session ID in HTTP-only cookie
    const cookieOptions = {
      httpOnly: true,
      maxAge: 60 * 60 * 1000, // 1 hour
      path: '/'
    };
    
    if (isRender) {
      cookieOptions.secure = true;
      cookieOptions.sameSite = 'none';
    } else if (isLocal) {
      cookieOptions.secure = false;
      cookieOptions.sameSite = 'lax';
    } else {
      cookieOptions.secure = true;
      cookieOptions.sameSite = 'strict';
    }
    
    res.cookie('session_id', sessionId, cookieOptions);
    
    // Generate Google OAuth URL
    const authUrl = oauth2Client.generateAuthUrl({
      access_type: 'offline',
      scope: [
        'https://www.googleapis.com/auth/calendar.readonly',
        'https://www.googleapis.com/auth/calendar.events',
        'openid',
        'email',
        'profile'
      ],
      state: sessionId,
      prompt: 'consent',
      include_granted_scopes: true
    });
    
    res.json({ 
      success: true, 
      authUrl,
      sessionId,
      redirectUri: REDIRECT_URI,
      frontendUrl: FRONTEND_URL
    });
  } catch (error) {
    console.error('Auth init error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to initialize authentication',
      details: isLocal ? error.message : undefined
    });
  }
});

/**
 * 2. Handle Google OAuth callback
 */
app.get('/api/auth/google/callback', async (req, res) => {
  try {
    const { code, state: sessionId, error: googleError } = req.query;
    
    if (googleError) {
      console.error('Google OAuth error:', googleError);
      throw new Error(`Google OAuth error: ${googleError}`);
    }
    
    if (!sessionId || !activeSessions.has(sessionId)) {
      console.error('Invalid session ID:', sessionId);
      throw new Error('Invalid session ID');
    }
    
    if (!code) {
      throw new Error('No authorization code received');
    }
    
    // Exchange code for tokens
    const { tokens } = await oauth2Client.getToken(code);
    
    // Get user info
    oauth2Client.setCredentials(tokens);
    const oauth2 = google.oauth2({ version: 'v2', auth: oauth2Client });
    const userInfo = await oauth2.userinfo.get();
    
    // Calculate expiry (1 hour from now, or use token expiry)
    const expiry = tokens.expiry_date || Date.now() + (60 * 60 * 1000);
    
    // Update session with tokens and user info
    activeSessions.set(sessionId, {
      tokens,
      userInfo: userInfo.data,
      expiry
    });
    
    console.log(`✅ User authenticated: ${userInfo.data.email}`);
    
    // Set session cookie
    const cookieOptions = {
      httpOnly: true,
      maxAge: 60 * 60 * 1000,
      path: '/'
    };
    
    if (isRender) {
      cookieOptions.secure = true;
      cookieOptions.sameSite = 'none';
    } else if (isLocal) {
      cookieOptions.secure = false;
      cookieOptions.sameSite = 'lax';
    } else {
      cookieOptions.secure = true;
      cookieOptions.sameSite = 'strict';
    }
    
    res.cookie('session_id', sessionId, cookieOptions);
    
    // Redirect to frontend homepage with success flag
    const redirectUrl = new URL(FRONTEND_URL);
    redirectUrl.searchParams.set('auth', 'success');
    
    res.redirect(redirectUrl.toString());
  } catch (error) {
    console.error('OAuth callback error:', error.message);
    
    // Redirect to frontend homepage with error
    const redirectUrl = new URL(FRONTEND_URL);
    redirectUrl.searchParams.set('auth', 'error');
    redirectUrl.searchParams.set('error', error.message);
    
    res.redirect(redirectUrl.toString());
  }
});

/**
 * 3. Check authentication status
 */
app.get('/api/auth/status', async (req, res) => {
  try {
    const validation = await validateSession(req);
    
    if (!validation.valid) {
      return res.json({ 
        authenticated: false, 
        error: validation.error 
      });
    }
    
    res.json({
      authenticated: true,
      user: validation.userInfo,
      sessionId: validation.sessionId,
      expiresIn: Math.max(0, validation.sessionData.expiry - Date.now())
    });
  } catch (error) {
    res.status(401).json({ 
      authenticated: false, 
      error: error.message 
    });
  }
});

/**
 * 4. Logout (clear session)
 */
app.post('/api/auth/logout', (req, res) => {
  try {
    const sessionId = req.cookies.session_id;
    
    if (sessionId) {
      activeSessions.delete(sessionId);
      transcriptionSessions.delete(sessionId);
    }
    
    // Clear session cookie
    const clearCookieOptions = {
      httpOnly: true,
      path: '/'
    };
    
    if (isRender) {
      clearCookieOptions.secure = true;
      clearCookieOptions.sameSite = 'none';
    } else if (isLocal) {
      clearCookieOptions.secure = false;
      clearCookieOptions.sameSite = 'lax';
    } else {
      clearCookieOptions.secure = true;
      clearCookieOptions.sameSite = 'strict';
    }
    
    res.clearCookie('session_id', clearCookieOptions);
    
    // Clear any express-session data
    if (req.session) {
      req.session.destroy();
    }
    
    res.json({ 
      success: true, 
      message: 'Logged out successfully' 
    });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to logout' 
    });
  }
});

/**
 * 5. Get OAuth configuration for frontend
 */
app.get('/api/auth/config', (req, res) => {
  res.json({
    clientId: GOOGLE_CLIENT_ID,
    redirectUri: REDIRECT_URI,
    frontendUrl: FRONTEND_URL,
    backendUrl: isRender ? FRONTEND_URL : `http://localhost:${PORT}`,
    scopes: [
      'https://www.googleapis.com/auth/calendar.readonly',
      'https://www.googleapis.com/auth/calendar.events',
      'openid',
      'email',
      'profile'
    ],
    environment: isRender ? 'render' : isLocal ? 'local' : 'production'
  });
});

// ==================== CALENDAR ENDPOINTS ====================

/**
 * 6. Get current meeting
 */
app.get('/api/calendar/current', async (req, res) => {
  try {
    const validation = await validateSession(req);
    
    if (!validation.valid) {
      return res.status(401).json({ 
        error: validation.error 
      });
    }
    
    const { calendar } = getCalendarClient(validation.sessionId);
    
    const now = new Date();
    const timeMin = new Date(now.getTime() - 2 * 60 * 60 * 1000).toISOString(); // 2 hours ago
    const timeMax = new Date(now.getTime() + 2 * 60 * 60 * 1000).toISOString(); // 2 hours from now
    
    const response = await calendar.events.list({
      calendarId: 'primary',
      timeMin,
      timeMax,
      maxResults: 20,
      singleEvents: true,
      orderBy: 'startTime'
    });
    
    const currentMeeting = getCurrentMeeting(response.data.items || []);
    
    if (!currentMeeting) {
      return res.json({ 
        hasMeeting: false,
        message: 'No current meeting found'
      });
    }
    
    res.json({
      hasMeeting: true,
      meeting: {
        id: currentMeeting.id,
        summary: currentMeeting.summary || 'Untitled Meeting',
        description: currentMeeting.description || '',
        start: currentMeeting.start,
        end: currentMeeting.end,
        location: currentMeeting.location,
        hangoutLink: currentMeeting.hangoutLink,
        conferenceData: currentMeeting.conferenceData,
        attendees: currentMeeting.attendees || [],
        created: currentMeeting.created,
        updated: currentMeeting.updated
      },
      currentTime: now.toISOString()
    });
  } catch (error) {
    console.error('Get current meeting error:', error.message);
    
    if (error.message.includes('Session not found') || error.message.includes('Session expired')) {
      return res.status(401).json({ 
        error: 'Authentication required',
        code: 'AUTH_REQUIRED'
      });
    }
    
    res.status(500).json({ 
      error: 'Failed to fetch current meeting',
      details: isLocal ? error.message : undefined
    });
  }
});

/**
 * 7. Get today's meetings
 */
app.get('/api/calendar/today', async (req, res) => {
  try {
    const validation = await validateSession(req);
    
    if (!validation.valid) {
      return res.status(401).json({ 
        error: validation.error 
      });
    }
    
    const { calendar } = getCalendarClient(validation.sessionId);
    
    const now = new Date();
    const startOfDay = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const endOfDay = new Date(now.getFullYear(), now.getMonth(), now.getDate() + 1);
    
    const response = await calendar.events.list({
      calendarId: 'primary',
      timeMin: startOfDay.toISOString(),
      timeMax: endOfDay.toISOString(),
      maxResults: 100,
      singleEvents: true,
      orderBy: 'startTime'
    });
    
    const meetings = response.data.items || [];
    const current = getCurrentMeeting(meetings);
    const upcoming = getUpcomingMeetings(meetings);
    
    res.json({
      current,
      upcoming,
      all: meetings,
      total: meetings.length,
      date: now.toISOString().split('T')[0]
    });
  } catch (error) {
    console.error('Get today meetings error:', error.message);
    res.status(500).json({ 
      error: 'Failed to fetch today\'s meetings',
      details: isLocal ? error.message : undefined
    });
  }
});

/**
 * 8. Create or update event with transcription
 */
app.post('/api/calendar/events', async (req, res) => {
  try {
    const validation = await validateSession(req);
    
    if (!validation.valid) {
      return res.status(401).json({ 
        error: validation.error 
      });
    }
    
    const { calendar, userInfo } = getCalendarClient(validation.sessionId);
    const { 
      eventId,
      summary,
      description,
      start,
      end,
      location,
      attendees,
      conferenceData,
      action = eventId ? 'update' : 'create'
    } = req.body;
    
    // Validate required fields for creation
    if (action === 'create' && (!summary || !start || !end)) {
      return res.status(400).json({
        error: 'Missing required fields: summary, start, and end are required'
      });
    }
    
    let event;
    let operation = action;
    
    if (action === 'update' && eventId) {
      // Update existing event
      const existingEvent = await calendar.events.get({
        calendarId: 'primary',
        eventId: eventId
      });
      
      const updatedEvent = {
        ...existingEvent.data,
        summary: summary || existingEvent.data.summary,
        description: description || existingEvent.data.description,
        location: location || existingEvent.data.location,
        attendees: attendees || existingEvent.data.attendees,
        conferenceData: conferenceData || existingEvent.data.conferenceData
      };
      
      // Only update start/end if provided
      if (start) updatedEvent.start = start;
      if (end) updatedEvent.end = end;
      
      const response = await calendar.events.update({
        calendarId: 'primary',
        eventId: eventId,
        resource: updatedEvent
      });
      
      event = response.data;
    } else {
      // Create new event
      const eventData = {
        summary,
        description: description || '',
        start: typeof start === 'string' ? { dateTime: start, timeZone: 'UTC' } : start,
        end: typeof end === 'string' ? { dateTime: end, timeZone: 'UTC' } : end,
        location: location || '',
        attendees: attendees || [],
        conferenceData: conferenceData || undefined,
        reminders: {
          useDefault: true
        }
      };
      
      const response = await calendar.events.insert({
        calendarId: 'primary',
        resource: eventData
      });
      
      event = response.data;
      operation = 'created';
    }
    
    // Store in transcription sessions if this is a transcription event
    if (description && description.includes('Transcription')) {
      if (!transcriptionSessions.has(validation.sessionId)) {
        transcriptionSessions.set(validation.sessionId, []);
      }
      
      const userTranscriptions = transcriptionSessions.get(validation.sessionId);
      userTranscriptions.push({
        eventId: event.id,
        summary: event.summary,
        timestamp: new Date().toISOString(),
        action: operation
      });
      
      // Keep only last 50 transcriptions
      if (userTranscriptions.length > 50) {
        transcriptionSessions.set(validation.sessionId, userTranscriptions.slice(-50));
      }
    }
    
    res.json({
      success: true,
      operation,
      event: {
        id: event.id,
        summary: event.summary,
        htmlLink: event.htmlLink,
        start: event.start,
        end: event.end,
        created: event.created,
        updated: event.updated
      },
      user: {
        email: userInfo.email,
        name: userInfo.name
      }
    });
  } catch (error) {
    console.error('Calendar event error:', error.message);
    
    if (error.message.includes('invalid_grant') || error.message.includes('token expired')) {
      return res.status(401).json({
        error: 'Authentication expired. Please reconnect.',
        code: 'TOKEN_EXPIRED'
      });
    }
    
    res.status(500).json({
      error: `Failed to ${req.body.action || 'process'} calendar event`,
      details: isLocal ? error.message : undefined
    });
  }
});

// ==================== HEALTH & INFO ENDPOINTS ====================

/**
 * Health check
 */
app.get('/api/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'google-calendar-transcription-api',
    timestamp: new Date().toISOString(),
    version: '2.0.0',
    environment: isRender ? 'render' : isLocal ? 'development' : 'production',
    deployment: {
      url: FRONTEND_URL,
      redirectUri: REDIRECT_URI,
      port: PORT
    },
    google: {
      clientId: GOOGLE_CLIENT_ID ? 'configured' : 'missing',
      hasSecret: !!GOOGLE_CLIENT_SECRET
    },
    sessions: {
      active: activeSessions.size,
      transcription: transcriptionSessions.size
    },
    uptime: process.uptime()
  });
});

/**
 * Server info
 */
app.get('/api/info', (req, res) => {
  res.json({
    name: 'Google Calendar Transcription API',
    description: 'Read/Write Google Calendar with temporary sessions',
    version: '2.0.0',
    environment: isRender ? 'render' : isLocal ? 'development' : 'production',
    deployment: FRONTEND_URL,
    supports: [
      'Google OAuth 2.0',
      'Calendar Read/Write',
      'Temporary Session Storage',
      'Render.com Compatible'
    ],
    endpoints: {
      auth: '/api/auth/*',
      calendar: '/api/calendar/*',
      health: '/api/health',
      info: '/api/info'
    }
  });
});

/**
 * Debug endpoint (only in development/Render)
 */
app.get('/api/debug', (req, res) => {
  if (!isLocal && !isRender) {
    return res.status(403).json({ error: 'Debug endpoint disabled in production' });
  }
  
  res.json({
    environment: {
      isLocal,
      isRender,
      NODE_ENV,
      PORT,
      RENDER_EXTERNAL_URL: process.env.RENDER_EXTERNAL_URL
    },
    urls: {
      FRONTEND_URL,
      REDIRECT_URI,
      currentUrl: `${req.protocol}://${req.get('host')}${req.originalUrl}`
    },
    google: {
      hasClientId: !!GOOGLE_CLIENT_ID,
      hasClientSecret: !!GOOGLE_CLIENT_SECRET,
      redirectUri: REDIRECT_URI
    },
    cookies: req.headers.cookie,
    headers: req.headers
  });
});

app.get('/auth/callback', (req, res) => {
  const { success, error, email, sessionId } = req.query;
  const ok = String(success).toLowerCase() === 'true';

  const postAuthRedirectBase = process.env.POST_AUTH_REDIRECT_URL || FRONTEND_URL;
  const redirectTarget = ok
    ? new URL(String(postAuthRedirectBase || ''), `${req.protocol}://${req.get('host')}`).toString()
    : '';

  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.status(200).send(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <title>Authentication ${ok ? 'Successful' : 'Failed'}</title>
    ${ok && redirectTarget ? `<meta http-equiv="refresh" content="2;url=${redirectTarget}">` : ''}
    <style>
      body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Cantarell,Noto Sans,sans-serif;margin:40px;line-height:1.5;color:#111}
      .card{max-width:720px;margin:0 auto;border:1px solid #e5e7eb;border-radius:12px;padding:24px}
      .ok{color:#065f46}
      .bad{color:#991b1b}
      code{background:#f3f4f6;padding:2px 6px;border-radius:6px}
    </style>
  </head>
  <body>
    <div class="card">
      <h1 class="${ok ? 'ok' : 'bad'}">${ok ? 'Connected to Google Calendar' : 'Authentication Failed'}</h1>
      ${ok ? `<p>Signed in as <code>${String(email || '')}</code>.</p>` : ''}
      ${!ok ? `<p class="bad">${String(error || 'Unknown error')}</p>` : ''}
      ${ok && redirectTarget ? `<p>Redirecting you back to the app…</p>` : `<p>You can close this tab and return to the app.</p>`}
      ${ok && redirectTarget ? `<p><a href="${redirectTarget}">Continue</a></p>` : ''}
      ${ok ? `<p><small>Session: <code>${String(sessionId || '')}</code></small></p>` : ''}
    </div>
    ${ok && redirectTarget ? `<script>setTimeout(function(){window.location.href=${JSON.stringify(redirectTarget)};},1500);</script>` : ''}
  </body>
</html>`);
});

// ==================== ERROR HANDLING ====================

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
    path: req.originalUrl,
    method: req.method,
    timestamp: new Date().toISOString(),
    availableEndpoints: {
      auth: '/api/auth/*',
      calendar: '/api/calendar/*',
      health: '/api/health',
      info: '/api/info',
      debug: '/api/debug'
    }
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Global error handler:', err);
  
  const statusCode = err.status || 500;
  const errorResponse = {
    error: err.message || 'Internal server error',
    timestamp: new Date().toISOString(),
    path: req.path,
    method: req.method
  };
  
  if (isLocal || isRender) {
    errorResponse.stack = err.stack;
    errorResponse.details = err.toString();
  }
  
  res.status(statusCode).json(errorResponse);
});

// ==================== STARTUP & CLEANUP ====================

// Periodic cleanup of expired sessions
setInterval(cleanupExpiredSessions, CLEANUP_INTERVAL);

// Cleanup on startup
cleanupExpiredSessions();

// Handle graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received. Cleaning up sessions...');
  activeSessions.clear();
  transcriptionSessions.clear();
  console.log('Cleanup complete. Shutting down.');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('SIGINT received. Shutting down gracefully...');
  activeSessions.clear();
  transcriptionSessions.clear();
  console.log('Cleanup complete. Shutting down.');
  process.exit(0);
});

// Start server
app.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════════════════════╗
║   🚀 Google Calendar Transcription API                  ║
║   📅 Read/Write with Temporary Sessions                ║
╚══════════════════════════════════════════════════════════╝

✅ Server is running!
📍 Port: ${PORT}
🌐 Environment: ${isRender ? 'Render.com' : isLocal ? 'Development' : 'Production'}
🔐 OAuth Client: ${GOOGLE_CLIENT_ID ? 'Configured' : 'MISSING!'}
🔄 Redirect URI: ${REDIRECT_URI}
🎯 Frontend URL: ${FRONTEND_URL}

📊 API Endpoints:
   🔐 Auth:     ${FRONTEND_URL}/api/auth/google
   📅 Calendar: ${FRONTEND_URL}/api/calendar/current
   ❤️  Health:    ${FRONTEND_URL}/api/health
   ℹ️  Info:      ${FRONTEND_URL}/api/info

⚠️  IMPORTANT Google Cloud Console Setup:
   1. Go to: https://console.cloud.google.com/apis/credentials
   2. Add to Authorized Redirect URIs:
      ${REDIRECT_URI}
   3. Add to Authorized JavaScript Origins:
      ${FRONTEND_URL}

🔒 Security Notes:
   - Sessions stored in memory only
   - Data lost on server restart
   - Session timeout: 1 hour
   - Automatic cleanup every 5 minutes

💡 Test immediately:
   curl ${FRONTEND_URL}/api/health
  `);
});
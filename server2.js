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
const PORT = process.env.PORT || 3001;
const NODE_ENV = process.env.NODE_ENV || 'development';
const isProduction = NODE_ENV === 'production';

// Google OAuth Configuration
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI || `http://localhost:${PORT}/api/auth/google/callback`;
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';

// Validate required environment variables
if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
  console.error('❌ ERROR: GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET are required in .env file');
  process.exit(1);
}

// ==================== MIDDLEWARE ====================

// CORS - Allow from anywhere with credentials
app.use(cors({
  origin: function(origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    // Allow all origins in development
    if (!isProduction) return callback(null, true);
    
    // In production, you might want to restrict origins
    // For now, allow all
    return callback(null, true);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin', 'Cookies', 'Set-Cookie'],
  exposedHeaders: ['Set-Cookie']
}));

// Handle preflight requests
app.options('*', cors());

// Request logging
app.use(morgan(isProduction ? 'combined' : 'dev'));

// Body parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Cookies and sessions
app.use(cookieParser());
app.use(session({
  name: 'calendar_session',
  secret: process.env.SESSION_SECRET || crypto.randomBytes(64).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: isProduction,
    httpOnly: true,
    sameSite: isProduction ? 'none' : 'lax',
    maxAge: 60 * 60 * 1000, // 1 hour
    domain: isProduction ? process.env.COOKIE_DOMAIN : undefined
  },
  store: new session.MemoryStore() // Use memory store for simplicity
}));

// Security headers
app.use((req, res, next) => {
  // Remove unnecessary headers
  res.removeHeader('X-Powered-By');
  
  // Add security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  
  if (isProduction) {
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
  
  if (cleaned > 0) {
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
    res.cookie('session_id', sessionId, {
      httpOnly: true,
      secure: isProduction,
      sameSite: isProduction ? 'none' : 'lax',
      maxAge: 60 * 60 * 1000, // 1 hour
      path: '/'
    });
    
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
      redirectUri: REDIRECT_URI 
    });
  } catch (error) {
    console.error('Auth init error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to initialize authentication' 
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
      throw new Error(`Google OAuth error: ${googleError}`);
    }
    
    if (!sessionId || !activeSessions.has(sessionId)) {
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
    
    // Set session cookie
    res.cookie('session_id', sessionId, {
      httpOnly: true,
      secure: isProduction,
      sameSite: isProduction ? 'none' : 'lax',
      maxAge: 60 * 60 * 1000,
      path: '/'
    });
    
    // Redirect to frontend with success
    const redirectUrl = new URL(`${FRONTEND_URL}/auth/callback`);
    redirectUrl.searchParams.set('success', 'true');
    redirectUrl.searchParams.set('sessionId', sessionId);
    redirectUrl.searchParams.set('email', userInfo.data.email || '');
    
    res.redirect(redirectUrl.toString());
  } catch (error) {
    console.error('OAuth callback error:', error.message);
    
    const redirectUrl = new URL(`${FRONTEND_URL}/auth/callback`);
    redirectUrl.searchParams.set('success', 'false');
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
    res.clearCookie('session_id', {
      httpOnly: true,
      secure: isProduction,
      sameSite: isProduction ? 'none' : 'lax',
      path: '/'
    });
    
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
    scopes: [
      'https://www.googleapis.com/auth/calendar.readonly',
      'https://www.googleapis.com/auth/calendar.events',
      'openid',
      'email',
      'profile'
    ],
    frontendUrl: FRONTEND_URL,
    apiUrl: `http://localhost:${PORT}` // Adjust for production
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
      details: error.message 
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
      details: error.message 
    });
  }
});

/**
 * 8. Get calendar events within date range
 */
app.get('/api/calendar/events', async (req, res) => {
  try {
    const validation = await validateSession(req);
    
    if (!validation.valid) {
      return res.status(401).json({ 
        error: validation.error 
      });
    }
    
    const { calendar } = getCalendarClient(validation.sessionId);
    const { 
      timeMin = new Date().toISOString(),
      timeMax = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(), // 7 days
      maxResults = 50,
      calendarId = 'primary'
    } = req.query;
    
    const response = await calendar.events.list({
      calendarId,
      timeMin,
      timeMax,
      maxResults: Math.min(parseInt(maxResults), 250),
      singleEvents: true,
      orderBy: 'startTime'
    });
    
    res.json({
      events: response.data.items || [],
      total: response.data.items?.length || 0,
      timeMin,
      timeMax,
      calendarId
    });
  } catch (error) {
    console.error('Get events error:', error.message);
    res.status(500).json({ 
      error: 'Failed to fetch calendar events',
      details: error.message 
    });
  }
});

/**
 * 9. Create or update event with transcription
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
      details: error.message
    });
  }
});

/**
 * 10. Append transcription to existing event
 */
app.patch('/api/calendar/events/:eventId/transcription', async (req, res) => {
  try {
    const validation = await validateSession(req);
    
    if (!validation.valid) {
      return res.status(401).json({ 
        error: validation.error 
      });
    }
    
    const { calendar, userInfo } = getCalendarClient(validation.sessionId);
    const { eventId } = req.params;
    const { transcription, timestamp, title = 'Meeting Notes' } = req.body;
    
    if (!transcription || !transcription.trim()) {
      return res.status(400).json({ 
        error: 'Transcription text is required' 
      });
    }
    
    // Get existing event
    const existingEvent = await calendar.events.get({
      calendarId: 'primary',
      eventId: eventId
    });
    
    const existingDescription = existingEvent.data.description || '';
    const noteTimestamp = timestamp || new Date().toLocaleString();
    const separator = existingDescription ? '\n\n---\n\n' : '';
    const transcriptionBlock = `## ${title} (${noteTimestamp})\n\n${transcription}`;
    
    const updatedEvent = {
      ...existingEvent.data,
      description: existingDescription + separator + transcriptionBlock
    };
    
    const response = await calendar.events.update({
      calendarId: 'primary',
      eventId: eventId,
      resource: updatedEvent
    });
    
    // Track this transcription
    if (!transcriptionSessions.has(validation.sessionId)) {
      transcriptionSessions.set(validation.sessionId, []);
    }
    
    const userTranscriptions = transcriptionSessions.get(validation.sessionId);
    userTranscriptions.push({
      eventId: eventId,
      summary: existingEvent.data.summary,
      transcriptionLength: transcription.length,
      timestamp: new Date().toISOString(),
      action: 'appended'
    });
    
    res.json({
      success: true,
      eventId: eventId,
      htmlLink: response.data.htmlLink,
      descriptionLength: response.data.description?.length || 0,
      user: {
        email: userInfo.email,
        name: userInfo.name
      }
    });
  } catch (error) {
    console.error('Append transcription error:', error.message);
    res.status(500).json({
      error: 'Failed to append transcription to event',
      details: error.message
    });
  }
});

/**
 * 11. Search calendar events
 */
app.get('/api/calendar/search', async (req, res) => {
  try {
    const validation = await validateSession(req);
    
    if (!validation.valid) {
      return res.status(401).json({ 
        error: validation.error 
      });
    }
    
    const { calendar } = getCalendarClient(validation.sessionId);
    const { 
      q = '',
      timeMin = new Date().toISOString(),
      timeMax = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(), // 30 days
      maxResults = 20,
      calendarId = 'primary'
    } = req.query;
    
    const response = await calendar.events.list({
      calendarId,
      q: q || undefined,
      timeMin,
      timeMax,
      maxResults: Math.min(parseInt(maxResults), 50),
      singleEvents: true,
      orderBy: 'startTime'
    });
    
    res.json({
      query: q,
      events: response.data.items || [],
      total: response.data.items?.length || 0,
      timeRange: { timeMin, timeMax }
    });
  } catch (error) {
    console.error('Search error:', error.message);
    res.status(500).json({ 
      error: 'Failed to search calendar',
      details: error.message 
    });
  }
});

// ==================== TRANSCRIPTION ENDPOINTS ====================

/**
 * 12. Start a transcription session
 */
app.post('/api/transcription/sessions', async (req, res) => {
  try {
    const validation = await validateSession(req);
    
    if (!validation.valid) {
      return res.status(401).json({ 
        error: validation.error 
      });
    }
    
    const { meetingId, meetingTitle, autoSave = true } = req.body;
    
    const sessionId = validation.sessionId;
    const sessionData = {
      sessionId,
      meetingId,
      meetingTitle: meetingTitle || 'Untitled Meeting',
      startTime: new Date().toISOString(),
      chunks: [],
      autoSave,
      status: 'active'
    };
    
    transcriptionSessions.set(sessionId, sessionData);
    
    res.json({
      success: true,
      sessionId,
      meetingId,
      meetingTitle: sessionData.meetingTitle,
      startTime: sessionData.startTime,
      autoSave
    });
  } catch (error) {
    console.error('Start transcription session error:', error);
    res.status(500).json({
      error: 'Failed to start transcription session',
      details: error.message
    });
  }
});

/**
 * 13. Add transcription chunk
 */
app.post('/api/transcription/chunks', async (req, res) => {
  try {
    const validation = await validateSession(req);
    
    if (!validation.valid) {
      return res.status(401).json({ 
        error: validation.error 
      });
    }
    
    const { text, isFinal = false, chunkIndex } = req.body;
    const sessionId = validation.sessionId;
    
    let sessionData = transcriptionSessions.get(sessionId);
    
    if (!sessionData) {
      // Create a new session if none exists
      sessionData = {
        sessionId,
        meetingId: null,
        meetingTitle: 'Live Transcription',
        startTime: new Date().toISOString(),
        chunks: [],
        autoSave: false,
        status: 'active'
      };
      transcriptionSessions.set(sessionId, sessionData);
    }
    
    const chunk = {
      text: text.trim(),
      isFinal,
      chunkIndex: chunkIndex || sessionData.chunks.length,
      timestamp: new Date().toISOString(),
      length: text.length
    };
    
    sessionData.chunks.push(chunk);
    sessionData.lastActivity = new Date().toISOString();
    
    // Auto-save to calendar if enabled and we have a meeting ID
    if (isFinal && sessionData.autoSave && sessionData.meetingId) {
      try {
        const { calendar } = getCalendarClient(sessionId);
        // Implementation for auto-saving would go here
      } catch (saveError) {
        console.error('Auto-save failed:', saveError.message);
      }
    }
    
    res.json({
      success: true,
      chunkId: chunk.chunkIndex,
      sessionId,
      totalChunks: sessionData.chunks.length,
      totalTextLength: sessionData.chunks.reduce((sum, c) => sum + c.length, 0)
    });
  } catch (error) {
    console.error('Add transcription chunk error:', error);
    res.status(500).json({
      error: 'Failed to add transcription chunk',
      details: error.message
    });
  }
});

/**
 * 14. Complete transcription and save to calendar
 */
app.post('/api/transcription/complete', async (req, res) => {
  try {
    const validation = await validateSession(req);
    
    if (!validation.valid) {
      return res.status(401).json({ 
        error: validation.error 
      });
    }
    
    const { saveToCalendar = true, meetingId, summary } = req.body;
    const sessionId = validation.sessionId;
    
    const sessionData = transcriptionSessions.get(sessionId);
    
    if (!sessionData) {
      return res.status(404).json({
        error: 'No active transcription session found'
      });
    }
    
    // Combine all final chunks
    const finalChunks = sessionData.chunks.filter(chunk => chunk.isFinal);
    const transcription = finalChunks.map(chunk => chunk.text).join(' ');
    
    if (transcription.length === 0) {
      return res.status(400).json({
        error: 'No transcription text to save'
      });
    }
    
    const result = {
      transcription,
      meetingId: meetingId || sessionData.meetingId,
      meetingTitle: summary || sessionData.meetingTitle,
      startTime: sessionData.startTime,
      endTime: new Date().toISOString(),
      duration: Date.now() - new Date(sessionData.startTime).getTime(),
      chunkCount: sessionData.chunks.length,
      finalChunkCount: finalChunks.length,
      totalLength: transcription.length
    };
    
    let calendarResult = null;
    
    // Save to calendar if requested and we have meeting ID
    if (saveToCalendar && result.meetingId) {
      try {
        const { calendar } = getCalendarClient(sessionId);
        
        // Get existing event
        const existingEvent = await calendar.events.get({
          calendarId: 'primary',
          eventId: result.meetingId
        });
        
        const existingDescription = existingEvent.data.description || '';
        const timestamp = new Date().toLocaleString();
        const separator = existingDescription ? '\n\n---\n\n' : '';
        const transcriptionBlock = `## Meeting Transcription (${timestamp})\n\n${transcription}`;
        
        const updatedEvent = {
          ...existingEvent.data,
          description: existingDescription + separator + transcriptionBlock
        };
        
        const response = await calendar.events.update({
          calendarId: 'primary',
          eventId: result.meetingId,
          resource: updatedEvent
        });
        
        calendarResult = {
          success: true,
          eventId: result.meetingId,
          htmlLink: response.data.htmlLink,
          descriptionLength: response.data.description?.length || 0
        };
      } catch (calendarError) {
        console.error('Calendar save error:', calendarError.message);
        calendarResult = {
          success: false,
          error: calendarError.message
        };
      }
    }
    
    // Clear the session
    transcriptionSessions.delete(sessionId);
    
    res.json({
      success: true,
      transcription: {
        ...result,
        preview: transcription.substring(0, 200) + (transcription.length > 200 ? '...' : '')
      },
      calendar: calendarResult,
      savedToCalendar: saveToCalendar && calendarResult?.success
    });
  } catch (error) {
    console.error('Complete transcription error:', error);
    res.status(500).json({
      error: 'Failed to complete transcription',
      details: error.message
    });
  }
});

/**
 * 15. Get transcription session status
 */
app.get('/api/transcription/sessions/:sessionId', (req, res) => {
  try {
    const { sessionId } = req.params;
    const sessionData = transcriptionSessions.get(sessionId);
    
    if (!sessionData) {
      return res.status(404).json({
        error: 'Transcription session not found'
      });
    }
    
    const finalChunks = sessionData.chunks.filter(chunk => chunk.isFinal);
    const transcription = finalChunks.map(chunk => chunk.text).join(' ');
    
    res.json({
      sessionId,
      meetingId: sessionData.meetingId,
      meetingTitle: sessionData.meetingTitle,
      startTime: sessionData.startTime,
      lastActivity: sessionData.lastActivity,
      status: sessionData.status,
      chunkCount: sessionData.chunks.length,
      finalChunkCount: finalChunks.length,
      transcriptionLength: transcription.length,
      transcriptionPreview: transcription.substring(0, 500) + (transcription.length > 500 ? '...' : ''),
      autoSave: sessionData.autoSave
    });
  } catch (error) {
    console.error('Get transcription session error:', error);
    res.status(500).json({
      error: 'Failed to get transcription session',
      details: error.message
    });
  }
});

// ==================== HEALTH & ADMIN ENDPOINTS ====================

/**
 * 16. Health check
 */
app.get('/api/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'google-calendar-transcription-api',
    timestamp: new Date().toISOString(),
    version: '1.0.0',
    environment: NODE_ENV,
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    sessions: {
      active: activeSessions.size,
      transcription: transcriptionSessions.size
    },
    google: {
      clientId: GOOGLE_CLIENT_ID ? 'configured' : 'missing',
      redirectUri: REDIRECT_URI
    }
  });
});

/**
 * 17. Get server info (public)
 */
app.get('/api/info', (req, res) => {
  res.json({
    name: 'Google Calendar Transcription API',
    description: 'Temporary OAuth-based calendar read/write with transcription',
    version: '1.0.0',
    environment: NODE_ENV,
    supports: [
      'Google OAuth 2.0',
      'Calendar Read/Write',
      'Live Transcription',
      'Temporary Session Storage',
      'CORS Enabled'
    ],
    endpoints: {
      auth: ['/api/auth/google', '/api/auth/status', '/api/auth/logout'],
      calendar: ['/api/calendar/current', '/api/calendar/today', '/api/calendar/events'],
      transcription: ['/api/transcription/sessions', '/api/transcription/chunks', '/api/transcription/complete']
    },
    repository: 'https://github.com/yourusername/calendar-transcription-api'
  });
});

/**
 * 18. Debug endpoint (only in development)
 */
app.get('/api/debug/sessions', (req, res) => {
  if (isProduction) {
    return res.status(403).json({ 
      error: 'Debug endpoint disabled in production' 
    });
  }
  
  const sessions = Array.from(activeSessions.entries()).map(([id, data]) => ({
    id,
    userEmail: data.userInfo?.email,
    userName: data.userInfo?.name,
    expiresIn: Math.max(0, data.expiry - Date.now()),
    hasTokens: !!data.tokens,
    tokenExpiry: data.tokens?.expiry_date ? new Date(data.tokens.expiry_date).toISOString() : null
  }));
  
  const transcriptions = Array.from(transcriptionSessions.entries()).map(([id, data]) => ({
    id,
    meetingId: data.meetingId,
    meetingTitle: data.meetingTitle,
    chunkCount: data.chunks?.length || 0,
    status: data.status,
    startTime: data.startTime
  }));
  
  res.json({
    totalActiveSessions: activeSessions.size,
    totalTranscriptionSessions: transcriptionSessions.size,
    sessions,
    transcriptionSessions: transcriptions,
    serverTime: new Date().toISOString(),
    cleanupInterval: CLEANUP_INTERVAL
  });
});

/**
 * 19. Clear all sessions (debug/emergency only)
 */
app.post('/api/debug/clear-all', (req, res) => {
  if (isProduction && req.query.force !== 'true') {
    return res.status(403).json({ 
      error: 'Use ?force=true in production to clear sessions' 
    });
  }
  
  const activeCount = activeSessions.size;
  const transcriptionCount = transcriptionSessions.size;
  
  activeSessions.clear();
  transcriptionSessions.clear();
  
  res.json({
    success: true,
    cleared: {
      activeSessions: activeCount,
      transcriptionSessions: transcriptionCount
    },
    timestamp: new Date().toISOString()
  });
});

// ==================== ERROR HANDLING ====================

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
    path: req.originalUrl,
    method: req.method,
    availableEndpoints: {
      auth: '/api/auth/*',
      calendar: '/api/calendar/*',
      transcription: '/api/transcription/*',
      health: '/api/health',
      info: '/api/info'
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
  
  if (!isProduction) {
    errorResponse.stack = err.stack;
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
🌐 Environment: ${NODE_ENV}
🔐 OAuth Client: ${GOOGLE_CLIENT_ID ? 'Configured' : 'MISSING!'}
🔄 Redirect URI: ${REDIRECT_URI}
🎯 Frontend URL: ${FRONTEND_URL}

📊 API Endpoints:
   🔐 Auth:     http://localhost:${PORT}/api/auth/google
   📅 Calendar: http://localhost:${PORT}/api/calendar/current
   🎤 Transcribe: http://localhost:${PORT}/api/transcription/sessions
   ❤️  Health:    http://localhost:${PORT}/api/health

⚠️  IMPORTANT: Sessions are stored in memory only
   - Data is lost on server restart
   - No persistent storage enabled
   - Perfect for privacy-focused applications

🔒 Security Notes:
   - CORS enabled from any origin
   - HTTPS required in production
   - Session timeout: 1 hour
   - Automatic cleanup every 5 minutes

💡 Next steps:
   1. Open frontend at ${FRONTEND_URL}
   2. Test auth flow
   3. Check calendar integration
   4. Deploy with Docker: 'docker-compose up -d'
  `);
});
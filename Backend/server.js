import express from 'express';
import { createClient } from '@supabase/supabase-js';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 10000;

// Initialize Supabase client
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY; // For server-side operations
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY; // For client-side operations

if (!supabaseUrl || !supabaseServiceKey || !supabaseAnonKey) {
    console.error('Missing required Supabase environment variables');
    process.exit(1);
}

// Service role client for admin operations
const supabaseAdmin = createClient(supabaseUrl, supabaseServiceKey, {
    auth: {
        autoRefreshToken: false,
        persistSession: false
    }
});

// Regular client for user operations
const supabase = createClient(supabaseUrl, supabaseAnonKey);

// Enhanced logging function
function log(level, message, data = null) {
    const timestamp = new Date().toISOString();
    console.log(`[${timestamp}] ${level}: ${message}`);
    if (data) {
        console.log('Data:', JSON.stringify(data, null, 2));
    }
}

// Middleware
app.use(cors({
    origin: ['http://localhost:5500', 'http://127.0.0.1:5500', 'http://localhost:5501', 'http://localhost:3000', 'https://kanjitenstudy.netlify.app'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '10mb' }));

// Add request parsing middleware with error handling
app.use((req, res, next) => {
    log('INFO', `${req.method} ${req.url}`);
    
    if (req.headers['content-type']) {
        log('DEBUG', 'Content-Type:', req.headers['content-type']);
    }
    
    if (req.body && Object.keys(req.body).length > 0) {
        const sanitizedBody = { ...req.body };
        if (sanitizedBody.password) {
            sanitizedBody.password = '[REDACTED]';
        }
        log('DEBUG', 'Request body:', sanitizedBody);
    }
    
    next();
});

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Stricter rate limiting for auth endpoints
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10
});
  
// Authentication middleware
async function authenticateUser(req, res, next) {
    const authHeader = req.headers.authorization;
    log('DEBUG', 'Auth header received:', authHeader ? 'Bearer token present' : 'No auth header');
    
    const token = authHeader?.replace('Bearer ', '');
    
    if (!token) {
        log('WARN', 'No session token provided');
        return res.status(401).json({ 
            success: false, 
            error: 'Access token required' 
        });
    }
    
    try {
        // Verify JWT token with Supabase
        const { data: { user }, error } = await supabase.auth.getUser(token);
        
        if (error || !user) {
            log('WARN', 'Invalid or expired session token', error);
            return res.status(401).json({ 
                success: false, 
                error: 'Invalid or expired session' 
            });
        }
        
        // Get user profile
        const { data: profile, error: profileError } = await supabase
            .from('profiles')
            .select('*')
            .eq('id', user.id)
            .single();
            
        if (profileError) {
            log('ERROR', 'Failed to get user profile', profileError);
            return res.status(500).json({ 
                success: false, 
                error: 'Failed to get user profile' 
            });
        }
        
        req.user = {
            id: user.id,
            email: user.email,
            ...profile
        };
        req.token = token;
        
        log('DEBUG', 'User authenticated successfully:', { userId: req.user.id, username: req.user.username });
        next();
        
    } catch (error) {
        log('ERROR', 'Authentication middleware error', error);
        res.status(500).json({ 
            success: false, 
            error: 'Authentication failed' 
        });
    }
}

app.get('/api/auth/verify', authenticateUser, async (req, res) => {
  try {
    // If we get here, the token is valid (authenticateUser middleware passed)
    const user = req.user;
    
    res.json({
      success: true,
      valid: true,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        isAnonymous: user.username?.startsWith('guest_') || false
      }
    });
    
  } catch (error) {
    console.error('Token verification error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Token verification failed' 
    });
  }
});
// Register endpoint using Supabase Auth
app.post('/api/auth/register', authLimiter, async (req, res) => {
    log('INFO', 'Registration attempt started');
    
    try {
        const { username, password, email } = req.body;
        
        // Input validation (keep existing validation code)
        if (!username || !password || !email) {
            return res.status(400).json({ error: 'All fields are required' });
        }
        
        if (username.length < 3 || username.length > 50) {
            return res.status(400).json({ error: 'Username must be 3-50 characters' });
        }
        
        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>]).{8,30}$/;
        if (!passwordRegex.test(password)) {
            return res.status(400).json({ 
                error: 'Password must be 8-30 characters with uppercase, lowercase, digit, and symbol' 
            });
        }
        
        // Check if username exists
        const { data: existingProfile, error: checkError } = await supabase
            .from('profiles')
            .select('id')
            .eq('username', username)
            .single();

        if (existingProfile && !checkError) {
            return res.status(400).json({ error: 'Username already exists' });
        }

        log('INFO', 'Username available, creating user account');
        
        // Create user with Supabase Auth
        const { data: authData, error: signUpError } = await supabase.auth.signUp({
            email,
            password,
            options: {
                data: {
                    username: username
                }
            }
        });

        if (signUpError) {
            log('ERROR', 'Supabase signup error', signUpError);
            return res.status(400).json({ error: signUpError.message });
        }

        if (!authData.user) {
            log('ERROR', 'No user returned from signup');
            return res.status(500).json({ error: 'User creation failed' });
        }

        // Check if email confirmation is required
        if (!authData.session) {
            log('INFO', 'Email confirmation required', { userId: authData.user.id, username });
            return res.json({
                success: true,
                needsConfirmation: true,
                message: 'Please check your email and click the confirmation link to activate your account.',
                user: {
                    id: authData.user.id,
                    username,
                    email,
                    isAnonymous: false
                }
            });
        }

        // If no email confirmation needed, proceed normally
        log('SUCCESS', 'User created successfully with immediate session', { userId: authData.user.id, username });

        res.json({
            success: true,
            user: {
                id: authData.user.id,
                username,
                email,
                isAnonymous: false
            },
            session: authData.session
        });
        
    } catch (error) {
        log('ERROR', 'Registration error', error);
        res.status(500).json({ error: 'Registration failed. Please try again.' });
    }
});

// 2. Add endpoint to check email confirmation status
app.post('/api/auth/check-confirmation', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password required' });
        }

        // Try to sign in - this will only work if email is confirmed
        const { data: authData, error: signInError } = await supabase.auth.signInWithPassword({
            email,
            password
        });

        if (signInError) {
            if (signInError.message.includes('Email not confirmed')) {
                return res.json({
                    success: false,
                    needsConfirmation: true,
                    message: 'Email not yet confirmed. Please check your email.'
                });
            }
            log('WARN', 'Confirmation check failed', signInError);
            return res.status(401).json({ error: 'Invalid credentials or email not confirmed' });
        }

        if (!authData.user || !authData.session) {
            return res.status(500).json({ error: 'Confirmation check failed' });
        }

        // Get user profile
        const { data: profile, error: profileError } = await supabase
            .from('profiles')
            .select('*')
            .eq('id', authData.user.id)
            .single();

        if (profileError) {
            log('ERROR', 'Failed to get user profile', profileError);
            return res.status(500).json({ error: 'Failed to get user profile' });
        }

        // Update last login
        await supabase
            .from('profiles')
            .update({ last_login: new Date().toISOString() })
            .eq('id', authData.user.id);

        log('SUCCESS', 'Email confirmed and user signed in', { userId: authData.user.id, username: profile.username });
        
        res.json({
            success: true,
            confirmed: true,
            user: {
                id: authData.user.id,
                username: profile.username,
                email: authData.user.email,
                isAnonymous: profile.is_anonymous
            },
            session: authData.session
        });
        
    } catch (error) {
        log('ERROR', 'Confirmation check error', error);
        res.status(500).json({ error: 'Failed to check confirmation status' });
    }
});

// 3. Add endpoint to resend confirmation email
app.post('/api/auth/resend-confirmation', async (req, res) => {
    try {
        const { email } = req.body;
        
        if (!email) {
            return res.status(400).json({ error: 'Email is required' });
        }

        const { error } = await supabase.auth.resend({
            type: 'signup',
            email: email
        });

        if (error) {
            log('ERROR', 'Failed to resend confirmation', error);
            return res.status(400).json({ error: error.message });
        }

        log('INFO', 'Confirmation email resent', { email });
        res.json({
            success: true,
            message: 'Confirmation email has been resent. Please check your inbox.'
        });
        
    } catch (error) {
        log('ERROR', 'Resend confirmation error', error);
        res.status(500).json({ error: 'Failed to resend confirmation email' });
    }
});

// Login endpoint using Supabase Auth
app.post('/api/auth/login', authLimiter, async (req, res) => {
    log('INFO', 'Login attempt started');
    
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            log('WARN', 'Login failed: Missing credentials');
            return res.status(400).json({ error: 'Email and password required' });
        }

        // Sign in with Supabase
        const { data: authData, error: signInError } = await supabase.auth.signInWithPassword({
            email,
            password
        });

        if (signInError) {
            log('WARN', 'Login failed', signInError);
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        if (!authData.user) {
            log('ERROR', 'No user returned from signin');
            return res.status(500).json({ error: 'Login failed' });
        }

        // Get user profile
        const { data: profile, error: profileError } = await supabase
            .from('profiles')
            .select('*')
            .eq('id', authData.user.id)
            .single();

        if (profileError) {
            log('ERROR', 'Failed to get user profile', profileError);
            return res.status(500).json({ error: 'Failed to get user profile' });
        }

        // Update last login
        await supabase
            .from('profiles')
            .update({ last_login: new Date().toISOString() })
            .eq('id', authData.user.id);

        log('SUCCESS', 'Login successful', { userId: authData.user.id, username: profile.username });
        
        res.json({
            success: true,
            user: {
                id: authData.user.id,
                username: profile.username,
                email: authData.user.email,
                isAnonymous: profile.is_anonymous
            },
            session: authData.session
        });
        
    } catch (error) {
        log('ERROR', 'Login error', error);
        res.status(500).json({ error: 'Login failed. Please try again.' });
    }
});

// Anonymous login (create temporary account)
app.post('/api/auth/anonymous', async (req, res) => {
    log('INFO', 'Anonymous login attempt');
    
    try {
        const guestUsername = `guest_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        const tempEmail = `${guestUsername}@temp.local`;
        const tempPassword = Math.random().toString(36) + Math.random().toString(36); // More secure temp password
        
        // Create anonymous user
        const { data: authData, error: signUpError } = await supabase.auth.signUp({
            email: tempEmail,
            password: tempPassword,
            options: {
                data: {
                    username: guestUsername,
                    is_anonymous: true
                }
            }
        });

        if (signUpError) {
            log('ERROR', 'Anonymous signup error', signUpError);
            return res.status(500).json({ error: 'Anonymous login failed' });
        }

        // Update profile to mark as anonymous
        if (authData.user) {
            await supabase
                .from('profiles')
                .update({ is_anonymous: true })
                .eq('id', authData.user.id);
        }

        log('SUCCESS', 'Anonymous login successful', { userId: authData.user?.id, guestUsername });

        res.json({
            success: true,
            user: {
                id: authData.user?.id,
                username: guestUsername,
                isAnonymous: true
            },
            session: authData.session
        });
    } catch (error) {
        log('ERROR', 'Anonymous login error', error);
        res.status(500).json({ error: 'Anonymous login failed' });
    }
});

// Logout endpoint
app.post('/api/auth/logout', authenticateUser, async (req, res) => {
    try {
        const { error } = await supabase.auth.signOut();
        
        if (error) {
            log('ERROR', 'Logout error', error);
            return res.status(500).json({ error: 'Logout failed' });
        }

        log('INFO', 'User logged out successfully');
        res.json({ success: true });
    } catch (error) {
        log('ERROR', 'Logout error', error);
        res.status(500).json({ error: 'Logout failed' });
    }
});

// Get user progress endpoint
app.get('/api/progress', authenticateUser, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('user_kanji_progress')
            .select('*')
            .eq('user_id', req.user.id);

        if (error) {
            log('ERROR', 'Failed to get user progress', error);
            return res.status(500).json({ error: 'Failed to get progress' });
        }

        res.json({ success: true, progress: data });
    } catch (error) {
        log('ERROR', 'Progress endpoint error', error);
        res.status(500).json({ error: 'Failed to get progress' });
    }
});

// Get user streak
app.get('/api/streak', authenticateUser, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('user_streaks')
            .select('daily_streak, last_review_date')
            .eq('user_id', req.user.id)
            .single();

        if (error && error.code !== 'PGRST116') {
            log('ERROR', 'Failed to get user streak', error);
            return res.status(500).json({ error: 'Failed to get streak' });
        }

        const streak = data ? {
            dailyStreak: data.daily_streak || 0,
            lastReviewDate: data.last_review_date
        } : { dailyStreak: 0, lastReviewDate: null };

        res.json({ success: true, streak });
    } catch (error) {
        log('ERROR', 'Streak get error', error);
        res.status(500).json({ error: 'Failed to get streak' });
    }
});

// Update streak when user completes a review
app.post('/api/streak/update', authenticateUser, async (req, res) => {
    try {
        const today = new Date().toISOString().split('T')[0]; // YYYY-MM-DD format
        
        // Get current streak
        const { data: currentStreak } = await supabase
            .from('user_streaks')
            .select('daily_streak, last_review_date')
            .eq('user_id', req.user.id)
            .single();

        let newStreak = 1;
        
        if (currentStreak) {
            const lastDate = currentStreak.last_review_date;
            const yesterday = new Date();
            yesterday.setDate(yesterday.getDate() - 1);
            const yesterdayStr = yesterday.toISOString().split('T')[0];
            
            if (lastDate === today) {
                // Already reviewed today, don't update
                return res.json({ success: true, streak: currentStreak.daily_streak });
            } else if (lastDate === yesterdayStr) {
                // Consecutive day, increment streak
                newStreak = currentStreak.daily_streak + 1;
            }
            // If gap > 1 day, streak resets to 1 (handled by newStreak = 1 above)
        }

        const streakData = {
            user_id: req.user.id,
            daily_streak: newStreak,
            last_review_date: today,
            updated_at: new Date().toISOString()
        };

        const { error } = await supabase
            .from('user_streaks')
            .upsert(streakData, {
                onConflict: 'user_id'
            });

        if (error) {
            log('ERROR', 'Failed to update streak', error);
            return res.status(500).json({ error: 'Failed to update streak' });
        }

        res.json({ success: true, streak: newStreak });
    } catch (error) {
        log('ERROR', 'Streak update error', error);
        res.status(500).json({ error: 'Failed to update streak' });
    }
});

// Bulk update kanji progress endpoint
app.post('/api/progress/bulk-update', authenticateUser, async (req, res) => {
    try {
        const { kanjiProgressData } = req.body;
        
        if (!kanjiProgressData || !Array.isArray(kanjiProgressData)) {
            return res.status(400).json({ error: 'Invalid kanji progress data' });
        }

        log('INFO', `Bulk updating progress for ${kanjiProgressData.length} kanji for user ${req.user.id}`);

        // Transform the data to match database schema
        const progressRecords = kanjiProgressData.map(([kanjiId, progressData]) => ({
            user_id: req.user.id,
            kanji_id: parseInt(kanjiId),
            learned: progressData.learned || false,
            in_review: progressData.inReview || false,
            srs_interval: progressData.interval || 1,
            ease_factor: progressData.ease || 2.5,
            consecutive_correct: progressData.consecutiveCorrect || 0,
            total_reviews: progressData.totalReviews || 0,
            correct_reviews: progressData.correctReviews || 0,
            last_review: progressData.lastReview || null,
            next_review: progressData.nextReview || null,
            mnemonic: progressData.mnemonic || null,
            updated_at: new Date().toISOString()
        }));

        // Use upsert to insert or update records
        const { error } = await supabase
            .from('user_kanji_progress')
            .upsert(progressRecords, {
                onConflict: 'user_id,kanji_id'
            });

        if (error) {
            log('ERROR', 'Failed to bulk update progress', error);
            return res.status(500).json({ error: 'Failed to update progress' });
        }

        log('SUCCESS', `Bulk updated ${kanjiProgressData.length} kanji progress records`);
        res.json({ success: true, updated: kanjiProgressData.length });
        
    } catch (error) {
        log('ERROR', 'Bulk progress update error', error);
        res.status(500).json({ error: 'Failed to update progress' });
    }
});
// Add these routes to your backend
// Update your existing backend code with these changes

// In the GET /api/settings endpoint, update the defaultSettings and settings objects:
// Updated GET /api/settings - Retrieve user settings including language
app.get('/api/settings', authenticateUser, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('user_settings')
            .select('*')
            .eq('user_id', req.user.id)
            .single();
        
        if (error && error.code !== 'PGRST116') { // PGRST116 = no rows returned
            log('ERROR', 'Failed to get user settings', error);
            return res.status(500).json({ error: 'Failed to get settings' });
        }
        
        // If no settings exist, return defaults
        const defaultSettings = {
            profileName: req.user.username || 'User',
            maxLevel: 10,
            jlptLevel: 'all',
            maxInterval: 180,
            showProgress: true,
            showDrawing: true,
            showStudyProgress: true,
            defaultQuestionMode: 'meaning-first',
            darkMode: false,
            language: 'en' // Add language default
        };
        
        const settings = data ? {
            profileName: data.profile_name || defaultSettings.profileName,
            maxLevel: data.max_level || defaultSettings.maxLevel,
            jlptLevel: data.jlpt_level || defaultSettings.jlptLevel,
            maxInterval: data.max_interval || defaultSettings.maxInterval,
            showProgress: data.show_progress !== null ? data.show_progress : defaultSettings.showProgress,
            showDrawing: data.show_drawing !== null ? data.show_drawing : defaultSettings.showDrawing,
            showStudyProgress: data.show_study_progress !== null ? data.show_study_progress : defaultSettings.showStudyProgress,
            defaultQuestionMode: data.default_question_mode || defaultSettings.defaultQuestionMode,
            darkMode: data.dark_mode !== null ? data.dark_mode : defaultSettings.darkMode,
            language: data.language || defaultSettings.language // Add language setting
        } : defaultSettings;
        
        res.json({ success: true, settings });
        
    } catch (error) {
        log('ERROR', 'Settings get error', error);
        res.status(500).json({ error: 'Failed to get settings' });
    }
});

// Updated PUT /api/settings - Save user settings including language
app.put('/api/settings', authenticateUser, async (req, res) => {
    try {
        // Add language to the destructuring
        const { 
            profileName, 
            maxLevel, 
            jlptLevel, 
            maxInterval, 
            showProgress, 
            showDrawing, 
            showStudyProgress,
            defaultQuestionMode, 
            darkMode,
            language // Add language parameter
        } = req.body;
        
        // Validate language parameter
        if (language && !['en', 'ja'].includes(language)) {
            return res.status(400).json({ error: 'Invalid language. Must be "en" or "ja"' });
        }
        
        const settingsData = {
            user_id: req.user.id,
            profile_name: profileName,
            max_level: maxLevel,
            jlpt_level: jlptLevel,
            max_interval: maxInterval,
            show_progress: showProgress,
            show_drawing: showDrawing,
            show_study_progress: showStudyProgress,
            default_question_mode: defaultQuestionMode,
            dark_mode: darkMode,
            language: language || 'en', // Add language to settings data
            updated_at: new Date().toISOString()
        };
        
        const { error } = await supabase
            .from('user_settings')
            .upsert(settingsData, {
                onConflict: 'user_id'
            });
            
        if (error) {
            log('ERROR', 'Failed to save settings', error);
            return res.status(500).json({ error: 'Failed to save settings' });
        }
        
        log('SUCCESS', 'Settings saved successfully', { 
            userId: req.user.id, 
            language: language 
        });
        res.json({ success: true });
        
    } catch (error) {
        log('ERROR', 'Settings save error', error);
        res.status(500).json({ error: 'Failed to save settings' });
    }
});

// Optional: Add endpoint to get user's language preference specifically
app.get('/api/user/language', authenticateUser, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('user_settings')
            .select('language')
            .eq('user_id', req.user.id)
            .single();
            
        if (error && error.code !== 'PGRST116') {
            log('ERROR', 'Failed to get user language', error);
            return res.status(500).json({ error: 'Failed to get language preference' });
        }
        
        const language = data?.language || 'en';
        res.json({ success: true, language });
        
    } catch (error) {
        log('ERROR', 'Language get error', error);
        res.status(500).json({ error: 'Failed to get language preference' });
    }
});

// Optional: Add endpoint to update language preference only
app.put('/api/user/language', authenticateUser, async (req, res) => {
    try {
        const { language } = req.body;
        
        // Validate language parameter
        if (!language || !['en', 'ja'].includes(language)) {
            return res.status(400).json({ error: 'Invalid language. Must be "en" or "ja"' });
        }
        
        const { error } = await supabase
            .from('user_settings')
            .upsert({
                user_id: req.user.id,
                language: language,
                updated_at: new Date().toISOString()
            }, {
                onConflict: 'user_id'
            });
            
        if (error) {
            log('ERROR', 'Failed to update language', error);
            return res.status(500).json({ error: 'Failed to update language preference' });
        }
        
        log('SUCCESS', 'Language updated successfully', { 
            userId: req.user.id, 
            language: language 
        });
        res.json({ success: true, language });
        
    } catch (error) {
        log('ERROR', 'Language update error', error);
        res.status(500).json({ error: 'Failed to update language preference' });
    }
});
// Update kanji progress endpoint
app.post('/api/progress/update', authenticateUser, async (req, res) => {
    try {
        const { kanji_id, learned, in_review, srs_interval, ease_factor, consecutive_correct, total_reviews, correct_reviews, next_review, mnemonic } = req.body;

        const progressData = {
            user_id: req.user.id,
            kanji_id,
            learned: learned || false,
            in_review: in_review || false,
            srs_interval: srs_interval || 1,
            ease_factor: ease_factor || 2.50,
            consecutive_correct: consecutive_correct || 0,
            total_reviews: total_reviews || 0,
            correct_reviews: correct_reviews || 0,
            last_review: new Date().toISOString(),
            next_review: next_review || null,
            mnemonic: mnemonic || null
        };

        const { data, error } = await supabase
            .from('user_kanji_progress')
            .upsert(progressData, {
                onConflict: 'user_id,kanji_id',
                returning: 'minimal'
            });

        if (error) {
            log('ERROR', 'Failed to update progress', error);
            return res.status(500).json({ error: 'Failed to update progress' });
        }

        res.json({ success: true });
    } catch (error) {
        log('ERROR', 'Progress update error', error);
        res.status(500).json({ error: 'Failed to update progress' });
    }
});

// Test database connection
app.get('/api/test-db', async (req, res) => {
    try {
        const { count: userCount, error: userError } = await supabase
            .from('profiles')
            .select('*', { count: 'exact', head: true });

        const { count: progressCount, error: progressError } = await supabase
            .from('user_kanji_progress')
            .select('*', { count: 'exact', head: true });

        if (userError || progressError) {
            throw new Error(userError?.message || progressError?.message);
        }
        
        res.json({
            success: true,
            database: 'connected',
            userCount: userCount || 0,
            progressCount: progressCount || 0,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        log('ERROR', 'Database test failed', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// Get custom words for a kanji
app.get('/api/custom-words/:kanjiId', authenticateUser, async (req, res) => {
    try {
        const { kanjiId } = req.params;
        
        const { data, error } = await supabase
            .from('user_custom_words')
            .select('*')
            .eq('user_id', req.user.id)
            .eq('kanji_id', parseInt(kanjiId))
            .order('created_at', { ascending: true });

        if (error) {
            log('ERROR', 'Failed to get custom words', error);
            return res.status(500).json({ error: 'Failed to get custom words' });
        }

        res.json({ success: true, words: data || [] });
    } catch (error) {
        log('ERROR', 'Custom words get error', error);
        res.status(500).json({ error: 'Failed to get custom words' });
    }
});

// Add custom word
app.post('/api/custom-words', authenticateUser, async (req, res) => {
    try {
        const { kanjiId, word, reading, meaning, wordType, jlptLevel } = req.body;
        
        // Check if user already has 3 words for this kanji
        const { count, error: countError } = await supabase
            .from('user_custom_words')
            .select('*', { count: 'exact', head: true })
            .eq('user_id', req.user.id)
            .eq('kanji_id', kanjiId);

        if (countError) {
            return res.status(500).json({ error: 'Failed to check word count' });
        }

        if (count >= 3) {
            return res.status(400).json({ error: 'Maximum 3 custom words per kanji' });
        }

        const { data, error } = await supabase
            .from('user_custom_words')
            .insert({
                user_id: req.user.id,
                kanji_id: parseInt(kanjiId),
                word,
                reading,
                meaning,
                word_type: wordType,
                jlpt_level: jlptLevel
            })
            .select()
            .single();

        if (error) {
            log('ERROR', 'Failed to add custom word', error);
            return res.status(500).json({ error: 'Failed to add custom word' });
        }

        res.json({ success: true, word: data });
    } catch (error) {
        log('ERROR', 'Custom word add error', error);
        res.status(500).json({ error: 'Failed to add custom word' });
    }
});

// Delete custom word
app.delete('/api/custom-words/:wordId', authenticateUser, async (req, res) => {
    try {
        const { wordId } = req.params;
        
        const { error } = await supabase
            .from('user_custom_words')
            .delete()
            .eq('id', wordId)
            .eq('user_id', req.user.id);

        if (error) {
            log('ERROR', 'Failed to delete custom word', error);
            return res.status(500).json({ error: 'Failed to delete custom word' });
        }

        res.json({ success: true });
    } catch (error) {
        log('ERROR', 'Custom word delete error', error);
        res.status(500).json({ error: 'Failed to delete custom word' });
    }
});

// Health check
app.get('/api/health', async (req, res) => {
    try {
        // Test Supabase connection
        const { error } = await supabase.from('profiles').select('id').limit(1);
        const dbConnected = !error;
        
        res.json({ 
            status: 'ok', 
            timestamp: new Date().toISOString(),
            port: PORT,
            database: dbConnected ? 'connected' : 'disconnected',
            environment: process.env.NODE_ENV || 'development'
        });
    } catch (error) {
        res.json({ 
            status: 'ok', 
            timestamp: new Date().toISOString(),
            port: PORT,
            database: 'disconnected',
            environment: process.env.NODE_ENV || 'development'
        });
    }
});

// Enhanced error handling middleware
app.use((error, req, res, next) => {
    log('ERROR', 'Unhandled error caught by middleware', {
        message: error.message,
        stack: error.stack,
        url: req.url,
        method: req.method
    });
    
    res.status(500).json({ 
        error: 'Internal server error',
        timestamp: new Date().toISOString()
    });
});

// Handle 404s - No wildcards, this catches all unmatched routes
app.use((req, res) => {
    log('WARN', '404 - Route not found', { url: req.originalUrl, method: req.method });
    res.status(404).json({ error: 'Route not found' });
});

// Start server
async function startServer() {
    try {
        log('INFO', 'Starting server initialization...');
        
        // Test Supabase connection
        const { error } = await supabase.from('profiles').select('id').limit(1);
        if (error) {
            log('WARN', 'Supabase connection test failed', error);
        } else {
            log('SUCCESS', 'Connected to Supabase');
        }
        
        app.listen(PORT,'0.0.0.0', () => {
            log('SUCCESS', `Server running on port ${PORT}`);
            log('INFO', `Health check: http://localhost:${PORT}/api/health`);
            log('INFO', `Database test: http://localhost:${PORT}/api/test-db`);
            log('INFO', `Environment: ${process.env.NODE_ENV || 'development'}`);
        });
        
    } catch (error) {
        log('ERROR', 'Failed to start server', error);
        process.exit(1);
    }
}

startServer();

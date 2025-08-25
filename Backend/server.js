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
        return res.status(401).json({ error: 'No session token provided' });
    }

    try {
        // Verify JWT token with Supabase
        const { data: { user }, error } = await supabase.auth.getUser(token);
        
        if (error || !user) {
            log('WARN', 'Invalid or expired session token', error);
            return res.status(401).json({ error: 'Invalid or expired session' });
        }

        // Get user profile
        const { data: profile, error: profileError } = await supabase
            .from('profiles')
            .select('*')
            .eq('id', user.id)
            .single();

        if (profileError) {
            log('ERROR', 'Failed to get user profile', profileError);
            return res.status(500).json({ error: 'Failed to get user profile' });
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
        res.status(500).json({ error: 'Authentication failed' });
    }
}

// Register endpoint using Supabase Auth
// Improved register endpoint with better error handling and profile creation
app.post('/api/auth/register', authLimiter, async (req, res) => {
    log('INFO', 'Registration attempt started');
    
    try {
        const { username, password, email } = req.body;
        
        // Input validation
        if (!username) {
            log('WARN', 'Registration failed: Missing username');
            return res.status(400).json({ 
                success: false, 
                error: 'Username is required' 
            });
        }
        
        if (!password) {
            log('WARN', 'Registration failed: Missing password');
            return res.status(400).json({ 
                success: false, 
                error: 'Password is required' 
            });
        }
        
        if (!email) {
            log('WARN', 'Registration failed: Missing email');
            return res.status(400).json({ 
                success: false, 
                error: 'Email is required' 
            });
        }
        
        // Username validation
        if (username.length < 3 || username.length > 50) {
            log('WARN', 'Registration failed: Invalid username length');
            return res.status(400).json({ 
                success: false, 
                error: 'Username must be 3-50 characters' 
            });
        }
        
        // Check for valid username characters (alphanumeric + underscore)
        const usernameRegex = /^[a-zA-Z0-9_]{3,50}$/;
        if (!usernameRegex.test(username)) {
            log('WARN', 'Registration failed: Invalid username characters');
            return res.status(400).json({ 
                success: false, 
                error: 'Username can only contain letters, numbers, and underscores' 
            });
        }
        
        // Password validation
        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>]).{8,30}$/;
        if (!passwordRegex.test(password)) {
            log('WARN', 'Registration failed: Password validation failed');
            return res.status(400).json({ 
                success: false, 
                error: 'Password must be 8-30 characters with uppercase, lowercase, digit, and symbol' 
            });
        }
        
        // Email validation
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            log('WARN', 'Registration failed: Invalid email format');
            return res.status(400).json({ 
                success: false, 
                error: 'Please enter a valid email address' 
            });
        }
        
        log('INFO', 'Input validation passed, checking username availability');
        
        // Check if username exists
        const { data: existingProfile, error: checkError } = await supabase
            .from('profiles')
            .select('id')
            .eq('username', username)
            .single();

        // If we get data back, username exists
        if (existingProfile && !checkError) {
            log('WARN', 'Registration failed: Username already exists', { username });
            return res.status(400).json({ 
                success: false, 
                error: 'Username already exists' 
            });
        }

        // Only proceed if no rows found (PGRST116 error is expected when no match)
        if (checkError && checkError.code !== 'PGRST116') {
            log('ERROR', 'Database error checking username', checkError);
            return res.status(500).json({ 
                success: false, 
                error: 'Database error during username check' 
            });
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
            
            // Handle specific Supabase errors
            let errorMessage = signUpError.message;
            if (signUpError.message.includes('already registered')) {
                errorMessage = 'An account with this email already exists';
            } else if (signUpError.message.includes('password')) {
                errorMessage = 'Password does not meet requirements';
            }
            
            return res.status(400).json({ 
                success: false, 
                error: errorMessage 
            });
        }

        if (!authData.user) {
            log('ERROR', 'No user returned from signup');
            return res.status(500).json({ 
                success: false, 
                error: 'User creation failed' 
            });
        }

        log('INFO', 'User created with Supabase Auth, creating profile');

        // Wait a moment for the database trigger to create the profile
        // (if you have a trigger) or create it manually
        await new Promise(resolve => setTimeout(resolve, 1000));

        // Verify profile was created or create it manually
        let { data: profile, error: profileError } = await supabase
            .from('profiles')
            .select('*')
            .eq('id', authData.user.id)
            .single();

        if (profileError && profileError.code === 'PGRST116') {
            // Profile doesn't exist, create it
            log('INFO', 'Creating user profile manually');
            const { data: newProfile, error: createProfileError } = await supabase
                .from('profiles')
                .insert([{
                    id: authData.user.id,
                    username: username,
                    email: email,
                    is_anonymous: false,
                    created_at: new Date().toISOString()
                }])
                .select()
                .single();

            if (createProfileError) {
                log('ERROR', 'Failed to create user profile', createProfileError);
                // Try to clean up the auth user if profile creation fails
                try {
                    await supabaseAdmin.auth.admin.deleteUser(authData.user.id);
                } catch (cleanupError) {
                    log('ERROR', 'Failed to cleanup user after profile creation failure', cleanupError);
                }
                return res.status(500).json({ 
                    success: false, 
                    error: 'Failed to create user profile' 
                });
            }

            profile = newProfile;
        } else if (profileError) {
            log('ERROR', 'Error checking user profile', profileError);
            return res.status(500).json({ 
                success: false, 
                error: 'Failed to verify user profile' 
            });
        }

        log('SUCCESS', 'User created successfully', { userId: authData.user.id, username });

        // Return success response
        res.json({
            success: true,
            user: {
                id: authData.user.id,
                username: profile.username,
                email: authData.user.email,
                isAnonymous: false
            },
            session: authData.session
        });
        
    } catch (error) {
        log('ERROR', 'Registration error', error);
        res.status(500).json({ 
            success: false, 
            error: 'Registration failed. Please try again.' 
        });
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
            showDrawing: true
        };

        const settings = data ? {
            profileName: data.profile_name || defaultSettings.profileName,
            maxLevel: data.max_level || defaultSettings.maxLevel,
            jlptLevel: data.jlpt_level || defaultSettings.jlptLevel,
            maxInterval: data.max_interval || defaultSettings.maxInterval,
            showProgress: data.show_progress !== null ? data.show_progress : defaultSettings.showProgress,
            showDrawing: data.show_drawing !== null ? data.show_drawing : defaultSettings.showDrawing
        } : defaultSettings;

        res.json({ success: true, settings });
        
    } catch (error) {
        log('ERROR', 'Settings get error', error);
        res.status(500).json({ error: 'Failed to get settings' });
    }
});

// Save user settings endpoint
app.put('/api/settings', authenticateUser, async (req, res) => {
    try {
        const { profileName, maxLevel, jlptLevel, maxInterval, showProgress, showDrawing } = req.body;
        
        const settingsData = {
            user_id: req.user.id,
            profile_name: profileName,
            max_level: maxLevel,
            jlpt_level: jlptLevel,
            max_interval: maxInterval,
            show_progress: showProgress,
            show_drawing: showDrawing,
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

        log('SUCCESS', 'Settings saved successfully', { userId: req.user.id });
        res.json({ success: true });
        
    } catch (error) {
        log('ERROR', 'Settings save error', error);
        res.status(500).json({ error: 'Failed to save settings' });
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

// =============================================================================
// OAuth2 AUTHORIZATION SERVER - BACKEND
// Node.js + Express Implementation
// Educational simulation of Google/GitHub OAuth2 flow
// =============================================================================
// SETUP INSTRUCTIONS:
// 1. npm init -y
// 2. npm install express cors body-parser crypto
// 3. node server.js
// 4. Server runs on http://localhost:3001
// =============================================================================

const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const crypto = require('crypto');

const app = express();
const PORT = 3001;

// =============================================================================
// MIDDLEWARE CONFIGURATION
// =============================================================================
app.use(cors());
app.use(bodyParser.json());
app.use(express.json());

// =============================================================================
// IN-MEMORY STORAGE (FOR DEMO ONLY)
// In production, use a proper database with encryption
// =============================================================================

// Authorized clients (in production, store in database)
const authorizedClients = {
    'demo-google-client-id': {
        name: 'Google OAuth Demo',
        secret: 'demo-google-secret-key',
        redirectUris: [
            'http://localhost:8080/callback',
            'http://localhost:3000/callback',
            'file:///callback',
            'http://localhost:8080/callback'
        ],
        provider: 'google'
    },
    'demo-github-client-id': {
        name: 'GitHub OAuth Demo',
        secret: 'demo-github-secret-key',
        redirectUris: [
            'http://localhost:8080/callback',
            'http://localhost:3000/callback',
            'file:///callback',
            'http://localhost:8080/callback'
        ],
        provider: 'github'
    }
};

// Issued authorization codes (temporary, with expiration)
const authorizationCodes = {};

// Issued access tokens
const accessTokens = {};

// Refresh tokens for token renewal
const refreshTokens = {};

// Mock users database (in production, integrate with real user DB)
const mockUsers = {
    'user_google_001': {
        id: 'user_google_001',
        provider: 'google',
        name: 'John Doe',
        email: 'john.doe@gmail.com',
        picture: 'https://via.placeholder.com/150'
    },
    'user_github_001': {
        id: 'user_github_001',
        provider: 'github',
        name: 'Jane Smith',
        email: 'jane.smith@github.com',
        picture: 'https://via.placeholder.com/150'
    }
};

// =============================================================================
// SECURITY CONFIGURATION
// =============================================================================
const AUTH_CODE_EXPIRY = 10 * 60 * 1000; // 10 minutes in milliseconds
const ACCESS_TOKEN_EXPIRY = 60 * 60; // 1 hour in seconds
const REFRESH_TOKEN_EXPIRY = 7 * 24 * 60 * 60; // 7 days in seconds

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

// Generate random tokens
function generateToken(length = 32) {
    return crypto.randomBytes(length).toString('hex');
}

// Log requests for debugging
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
    next();
});

// Validate state parameter (CSRF protection)
function validateState(state, session) {
    return state && session && state === session;
}

// =============================================================================
// OAuth2 ENDPOINTS
// =============================================================================

// Health check
app.get('/', (req, res) => {
    res.json({
        service: 'OAuth2 Authorization Server',
        status: 'running',
        version: '1.0.0',
        description: 'Educational OAuth2 flow simulation'
    });
});

// =============================================================================
// STEP 1: AUTHORIZATION ENDPOINT
// POST /oauth2/authorize
// Client requests authorization code from user
// =============================================================================
app.post('/oauth2/authorize', (req, res) => {
    try {
        const { provider, clientId, redirectUri, scope, state } = req.body;

        console.log(`\n${'='.repeat(60)}`);
        console.log('📋 STEP 1: AUTHORIZATION REQUEST');
        console.log('='.repeat(60));
        console.log(`Provider: ${provider}`);
        console.log(`Client ID: ${clientId}`);
        console.log(`Redirect URI Received: ${redirectUri}`);
        console.log(`Scope: ${scope}`);
        console.log(`State: ${state}`);
        console.log(`Authorized URIs for this client: ${JSON.stringify(authorizedClients[clientId]?.redirectUris)}`);

        // Validate client
        if (!authorizedClients[clientId]) {
            console.log('❌ Invalid client ID');
            return res.status(400).json({
                success: false,
                message: 'Invalid client ID'
            });
        }

        const client = authorizedClients[clientId];

        // Validate redirect URI
        if (!client.redirectUris.includes(redirectUri)) {
            console.log('❌ Invalid redirect URI');
            return res.status(400).json({
                success: false,
                message: 'Invalid redirect URI'
            });
        }

        // Generate authorization code
        const authCode = generateToken(20);
        const expiresAt = Date.now() + AUTH_CODE_EXPIRY;

        // Store authorization code with metadata
        authorizationCodes[authCode] = {
            clientId,
            redirectUri,
            scope,
            state,
            provider,
            expiresAt,
            userId: 'user_' + provider + '_001' // Simulated user
        };

        console.log(`✅ Authorization code generated: ${authCode}`);
        console.log(`⏰ Expires at: ${new Date(expiresAt).toISOString()}`);
        console.log(`📦 Total codes stored: ${Object.keys(authorizationCodes).length}`);
        console.log('='.repeat(60) + '\n');

        res.json({
            success: true,
            authorizationCode: authCode,
            state,
            expiresIn: AUTH_CODE_EXPIRY / 1000,
            message: 'Authorization code generated. Exchange it for access token.'
        });

    } catch (error) {
        console.error('Authorization error:', error);
        res.status(500).json({
            success: false,
            message: 'Authorization failed',
            error: error.message
        });
    }
});

// =============================================================================
// STEP 2: TOKEN ENDPOINT
// POST /oauth2/token
// Client exchanges authorization code for access token
// =============================================================================
app.post('/oauth2/token', (req, res) => {
    try {
        const { grantType, code, clientId, redirectUri, provider } = req.body;

        console.log(`\n${'='.repeat(60)}`);
        console.log('🔑 STEP 2: TOKEN REQUEST (CODE EXCHANGE)');
        console.log('='.repeat(60));
        console.log(`Grant Type: ${grantType}`);
        console.log(`Authorization Code: ${code.substring(0, 10)}...`);
        console.log(`Client ID: ${clientId}`);
        console.log(`Provider: ${provider}`);

        // Validate grant type
        if (grantType !== 'authorization_code') {
            console.log('❌ Invalid grant type');
            return res.status(400).json({
                success: false,
                message: 'Invalid grant type'
            });
        }

        // Validate authorization code exists and is not expired
        if (!authorizationCodes[code]) {
            console.log('❌ Invalid or expired authorization code');
            return res.status(400).json({
                success: false,
                message: 'Invalid or expired authorization code'
            });
        }

        const authCodeData = authorizationCodes[code];

        // Validate code hasn't expired
        if (Date.now() > authCodeData.expiresAt) {
            delete authorizationCodes[code];
            console.log('❌ Authorization code expired');
            return res.status(400).json({
                success: false,
                message: 'Authorization code has expired'
            });
        }

        // Validate client ID and redirect URI match
        if (authCodeData.clientId !== clientId || authCodeData.redirectUri !== redirectUri) {
            console.log('❌ Client ID or redirect URI mismatch');
            return res.status(400).json({
                success: false,
                message: 'Client ID or redirect URI does not match'
            });
        }

        // Generate access token and refresh token
        const accessToken = generateToken(40);
        const refreshToken = generateToken(40);
        const expiresIn = ACCESS_TOKEN_EXPIRY;

        // Store access token
        accessTokens[accessToken] = {
            clientId,
            userId: authCodeData.userId,
            scope: authCodeData.scope,
            provider: authCodeData.provider,
            issuedAt: Date.now(),
            expiresAt: Date.now() + (expiresIn * 1000)
        };

        // Store refresh token
        refreshTokens[refreshToken] = {
            clientId,
            userId: authCodeData.userId,
            scope: authCodeData.scope,
            provider: authCodeData.provider,
            issuedAt: Date.now(),
            expiresAt: Date.now() + (REFRESH_TOKEN_EXPIRY * 1000)
        };

        // Invalidate authorization code (single-use)
        delete authorizationCodes[code];

        console.log(`✅ Access token generated: ${accessToken.substring(0, 20)}...`);
        console.log(`✅ Refresh token generated: ${refreshToken.substring(0, 20)}...`);
        console.log(`⏰ Token expires in: ${expiresIn} seconds`);
        console.log(`📦 Total access tokens: ${Object.keys(accessTokens).length}`);
        console.log('='.repeat(60) + '\n');

        res.json({
            success: true,
            accessToken,
            refreshToken,
            tokenType: 'Bearer',
            expiresIn,
            scope: authCodeData.scope,
            message: 'Token exchange successful'
        });

    } catch (error) {
        console.error('Token exchange error:', error);
        res.status(500).json({
            success: false,
            message: 'Token exchange failed',
            error: error.message
        });
    }
});

// =============================================================================
// STEP 3: USERINFO ENDPOINT
// POST /oauth2/userinfo
// Client uses access token to get user information
// =============================================================================
app.post('/oauth2/userinfo', (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        const { provider } = req.body;

        console.log(`\n${'='.repeat(60)}`);
        console.log('👤 STEP 3: USER INFO REQUEST');
        console.log('='.repeat(60));
        console.log(`Authorization Header: ${authHeader ? authHeader.substring(0, 20) + '...' : 'Missing'}`);
        console.log(`Provider: ${provider}`);

        // Validate authorization header
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            console.log('❌ Missing or invalid authorization header');
            return res.status(401).json({
                success: false,
                message: 'Missing or invalid authorization header'
            });
        }

        // Extract token
        const token = authHeader.substring(7);

        // Validate token exists and is not expired
        if (!accessTokens[token]) {
            console.log('❌ Invalid or expired access token');
            return res.status(401).json({
                success: false,
                message: 'Invalid or expired access token'
            });
        }

        const tokenData = accessTokens[token];

        // Validate token hasn't expired
        if (Date.now() > tokenData.expiresAt) {
            delete accessTokens[token];
            console.log('❌ Access token expired');
            return res.status(401).json({
                success: false,
                message: 'Access token has expired'
            });
        }

        // Get user information
        const userId = tokenData.userId;
        const user = mockUsers[userId];

        if (!user) {
            console.log('❌ User not found');
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        console.log(`✅ User found: ${user.name}`);
        console.log(`📧 Email: ${user.email}`);
        console.log(`🆔 User ID: ${user.id}`);
        console.log(`🔐 Scope granted: ${tokenData.scope}`);
        console.log('='.repeat(60) + '\n');

        // Return user info based on scope
        const userInfo = {
            id: user.id,
            name: user.name,
            email: user.email,
            picture: user.picture,
            provider: user.provider,
            email_verified: true
        };

        res.json({
            success: true,
            user: userInfo,
            message: 'User information retrieved successfully'
        });

    } catch (error) {
        console.error('User info error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to retrieve user info',
            error: error.message
        });
    }
});

// =============================================================================
// TOKEN REFRESH ENDPOINT
// POST /oauth2/refresh-token
// Client uses refresh token to get new access token
// =============================================================================
app.post('/oauth2/refresh-token', (req, res) => {
    try {
        const { refreshToken, clientId } = req.body;

        console.log(`\n${'='.repeat(60)}`);
        console.log('🔄 TOKEN REFRESH REQUEST');
        console.log('='.repeat(60));
        console.log(`Client ID: ${clientId}`);

        // Validate refresh token
        if (!refreshTokens[refreshToken]) {
            console.log('❌ Invalid refresh token');
            return res.status(400).json({
                success: false,
                message: 'Invalid refresh token'
            });
        }

        const refreshTokenData = refreshTokens[refreshToken];

        // Validate token hasn't expired
        if (Date.now() > refreshTokenData.expiresAt) {
            delete refreshTokens[refreshToken];
            console.log('❌ Refresh token expired');
            return res.status(400).json({
                success: false,
                message: 'Refresh token has expired'
            });
        }

        // Validate client ID matches
        if (refreshTokenData.clientId !== clientId) {
            console.log('❌ Client ID mismatch');
            return res.status(400).json({
                success: false,
                message: 'Client ID does not match'
            });
        }

        // Generate new access token
        const newAccessToken = generateToken(40);
        const expiresIn = ACCESS_TOKEN_EXPIRY;

        accessTokens[newAccessToken] = {
            clientId: refreshTokenData.clientId,
            userId: refreshTokenData.userId,
            scope: refreshTokenData.scope,
            provider: refreshTokenData.provider,
            issuedAt: Date.now(),
            expiresAt: Date.now() + (expiresIn * 1000)
        };

        console.log(`✅ New access token generated: ${newAccessToken.substring(0, 20)}...`);
        console.log('='.repeat(60) + '\n');

        res.json({
            success: true,
            accessToken: newAccessToken,
            tokenType: 'Bearer',
            expiresIn,
            message: 'Token refreshed successfully'
        });

    } catch (error) {
        console.error('Token refresh error:', error);
        res.status(500).json({
            success: false,
            message: 'Token refresh failed',
            error: error.message
        });
    }
});

// =============================================================================
// DEBUG/ADMIN ENDPOINTS (Remove in production!)
// =============================================================================

// List all issued tokens
app.get('/debug/tokens', (req, res) => {
    res.json({
        authorizationCodes: {
            count: Object.keys(authorizationCodes).length,
            codes: Object.keys(authorizationCodes).map(code => ({
                code: code.substring(0, 10) + '...',
                provider: authorizationCodes[code].provider,
                expiresAt: new Date(authorizationCodes[code].expiresAt).toISOString()
            }))
        },
        accessTokens: {
            count: Object.keys(accessTokens).length,
            tokens: Object.keys(accessTokens).map(token => ({
                token: token.substring(0, 10) + '...',
                provider: accessTokens[token].provider,
                expiresAt: new Date(accessTokens[token].expiresAt).toISOString()
            }))
        },
        refreshTokens: {
            count: Object.keys(refreshTokens).length
        }
    });
});

// Cleanup expired tokens
app.post('/debug/cleanup', (req, res) => {
    let cleaned = 0;

    // Clean expired authorization codes
    Object.keys(authorizationCodes).forEach(code => {
        if (Date.now() > authorizationCodes[code].expiresAt) {
            delete authorizationCodes[code];
            cleaned++;
        }
    });

    // Clean expired access tokens
    Object.keys(accessTokens).forEach(token => {
        if (Date.now() > accessTokens[token].expiresAt) {
            delete accessTokens[token];
            cleaned++;
        }
    });

    // Clean expired refresh tokens
    Object.keys(refreshTokens).forEach(token => {
        if (Date.now() > refreshTokens[token].expiresAt) {
            delete refreshTokens[token];
            cleaned++;
        }
    });

    res.json({
        success: true,
        cleaned,
        message: `Cleaned ${cleaned} expired tokens`
    });
});

// =============================================================================
// 404 HANDLER
// =============================================================================
app.use('*', (req, res) => {
    res.status(404).json({
        success: false,
        message: 'Endpoint not found',
        availableEndpoints: [
            'POST /oauth2/authorize - Step 1: Request authorization code',
            'POST /oauth2/token - Step 2: Exchange code for token',
            'POST /oauth2/userinfo - Step 3: Get user information',
            'POST /oauth2/refresh-token - Refresh access token',
            'GET /debug/tokens - List all tokens (debug)',
            'POST /debug/cleanup - Clean expired tokens (debug)'
        ]
    });
});

// =============================================================================
// ERROR HANDLER
// =============================================================================
app.use((error, req, res, next) => {
    console.error('Unhandled error:', error);
    res.status(500).json({
        success: false,
        message: 'Internal server error'
    });
});

// =============================================================================
// SERVER STARTUP
// =============================================================================
app.listen(PORT, () => {
    console.log('='.repeat(60));
    console.log('🔐 OAuth2 AUTHORIZATION SERVER STARTED');
    console.log('='.repeat(60));
    console.log(`📡 Server running on http://localhost:${PORT}`);
    console.log('\n⚙️  OAuth2 Configuration:');
    console.log(`   Authorization Code Expiry: ${AUTH_CODE_EXPIRY / 1000 / 60} minutes`);
    console.log(`   Access Token Expiry: ${ACCESS_TOKEN_EXPIRY / 60 / 60} hour(s)`);
    console.log(`   Refresh Token Expiry: ${REFRESH_TOKEN_EXPIRY / 24 / 60 / 60} day(s)`);
    console.log('\n📋 Available Endpoints:');
    console.log('   POST /oauth2/authorize - Authorization endpoint');
    console.log('   POST /oauth2/token - Token endpoint');
    console.log('   POST /oauth2/userinfo - UserInfo endpoint');
    console.log('   POST /oauth2/refresh-token - Refresh token endpoint');
    console.log('\n🐛 Debug Endpoints:');
    console.log('   GET /debug/tokens - View token statistics');
    console.log('   POST /debug/cleanup - Clean expired tokens');
    console.log('\n⚠️  This is an educational demo. Use proper OAuth2 libraries in production!');
    console.log('='.repeat(60) + '\n');
});
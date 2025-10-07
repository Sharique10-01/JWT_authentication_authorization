// ============================================================================
// REFRESH TOKEN REQUEST DTO - DATA TRANSFER OBJECT FOR TOKEN REFRESH
// ============================================================================
// PURPOSE: Request new access token using refresh token
//
// WHEN USED:
// When the access token expires and client needs a new one without re-login
//
// TYPICAL SCENARIO:
// 1. User logged in yesterday (Day 1)
// 2. Today (Day 2), access token expired
// 3. Client automatically sends this DTO to /api/auth/refresh-token
// 4. Server validates and returns new tokens
// 5. User stays logged in seamlessly!
//
// WHY BOTH FIELDS?
// - UserId: To find the user in database
// - RefreshToken: To verify this is the correct refresh token for that user
//
// SECURITY: Server checks BOTH fields match what's in the database
// ============================================================================

namespace JwtAuthDotNet9.Models
{
    public class RefreshTokenRequestDto
    {
        // ====================================================================
        // PROPERTY 1: USER ID
        // ====================================================================
        // PURPOSE: Identify which user is requesting token refresh
        //
        // TYPE: Guid (Globally Unique Identifier)
        // EXAMPLE: "123e4567-e89b-12d3-a456-426614174000"
        //
        // WHY NEEDED?
        // - Database lookup: Find user by ID
        // - Fast query: Primary key lookup is very fast
        // - No scanning: Don't have to search all refresh tokens
        //
        // WHERE DOES CLIENT GET THIS?
        // From login response or from the JWT token payload:
        //
        // Option 1 (Recommended): Extract from expired JWT
        //   const decodedToken = jwt_decode(expiredAccessToken);
        //   const userId = decodedToken.nameid;  // ClaimTypes.NameIdentifier
        //
        // Option 2: Store during login
        //   localStorage.setItem('userId', response.userId);
        //
        // FLOW:
        // 1. Client has expired access token
        // 2. Client extracts userId from token (even expired tokens are readable!)
        // 3. Client sends userId + refreshToken to server
        // 4. Server finds user: var user = await context.Users.FindAsync(userId);
        // 5. Server validates refresh token matches
        //
        // SECURITY NOTE:
        // - User ID alone is NOT enough to get new tokens!
        // - Must also have valid refresh token
        // - Both must match what's in database
        // ====================================================================
        public Guid UserId { get; set; }

        // ====================================================================
        // PROPERTY 2: REFRESH TOKEN
        // ====================================================================
        // PURPOSE: Prove client has valid session
        //
        // TYPE: string (Base64-encoded random bytes)
        // EXAMPLE: "xK9pLm3nQ4r7sT8uV2wX5yZ6A1bC2dE3fG4hI5jK6="
        //
        // WHY "required"?
        // - C# 11 feature: Must be provided when creating object
        // - Prevents null refresh token
        // - Compile-time safety
        //
        // WHERE DOES CLIENT GET THIS?
        // From login or previous refresh response:
        //   localStorage.setItem('refreshToken', response.refreshToken);
        //
        // VALIDATION ON SERVER:
        // Server performs THREE checks:
        //
        // 1. USER EXISTS:
        //    var user = await context.Users.FindAsync(request.UserId);
        //    if (user == null) → Invalid (user deleted?)
        //
        // 2. TOKEN MATCHES:
        //    if (user.RefreshToken != request.RefreshToken) → Invalid
        //    This prevents random guessing or stolen user IDs
        //
        // 3. NOT EXPIRED:
        //    if (user.RefreshTokenExpiryTime <= DateTime.UtcNow) → Invalid
        //    Refresh token only valid for 7 days
        //
        // ALL THREE MUST PASS for refresh to succeed!
        //
        // SECURITY FEATURES:
        // 1. RANDOM:
        //    - 256 bits of cryptographic randomness
        //    - Impossible to guess
        //
        // 2. SINGLE USE (Token Rotation):
        //    - After successful refresh, NEW refresh token is generated
        //    - Old token is replaced in database
        //    - If someone steals token, can only use once
        //    - Original user will get error next time (knows something's wrong!)
        //
        // 3. STORED IN DATABASE:
        //    - Can be revoked (set to null on logout)
        //    - Can't be used if user account is deleted/banned
        //
        // 4. EXPIRATION:
        //    - Only valid for 7 days
        //    - Forces periodic re-authentication
        //
        // EXAMPLE ATTACK SCENARIO:
        // Hacker steals refresh token "xK9pL..."
        //   1. Hacker uses it → Gets new tokens (old token now invalid)
        //   2. Real user tries to refresh → Error! (token was already used)
        //   3. Real user knows something is wrong
        //   4. Real user logs in again → Gets new refresh token
        //   5. Hacker's stolen tokens now useless
        // ====================================================================
        public required string RefreshToken { get; set; }
    }
}

// ============================================================================
// HOW THIS DTO IS USED IN PRACTICE
// ============================================================================
//
// SCENARIO: User's access token expired
// ======================================
//
// STEP 1: CLIENT DETECTS EXPIRATION
// ----------------------------------
// User tries to access protected endpoint:
//
// fetch('/api/auth', {
//   headers: { 'Authorization': `Bearer ${expiredToken}` }
// })
//
// Server response: 401 Unauthorized
//
// STEP 2: CLIENT PREPARES REFRESH REQUEST
// ----------------------------------------
// Client extracts userId from expired token:
//
// const decodedToken = jwt_decode(expiredAccessToken);
// const userId = decodedToken.nameid;  // "123e4567-e89b-12d3-a456-426614174000"
//
// Client retrieves stored refresh token:
//
// const refreshToken = localStorage.getItem('refreshToken');  // "xK9pL..."
//
// STEP 3: CLIENT SENDS REFRESH REQUEST
// -------------------------------------
// POST /api/auth/refresh-token
// Body: {
//   "userId": "123e4567-e89b-12d3-a456-426614174000",
//   "refreshToken": "xK9pLm3nQ4r7sT8uV2wX5yZ6A1bC2dE3fG4hI5jK6="
// }
//
// .NET deserializes to RefreshTokenRequestDto
//
// STEP 4: SERVER VALIDATES (AuthService.RefreshTokensAsync)
// ----------------------------------------------------------
// var user = await context.Users.FindAsync(request.UserId);
//
// Validation checks:
// 1. if (user == null) → Return null
// 2. if (user.RefreshToken != request.RefreshToken) → Return null
// 3. if (user.RefreshTokenExpiryTime <= DateTime.UtcNow) → Return null
//
// All valid? → Create new tokens!
//
// STEP 5: SERVER CREATES NEW TOKENS
// ----------------------------------
// 1. Create new JWT access token (expires in 1 day)
// 2. Create new refresh token (random string)
// 3. Update database:
//    user.RefreshToken = newRefreshToken;
//    user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);
// 4. Save changes
// 5. Return TokenResponseDto
//
// STEP 6: CLIENT STORES NEW TOKENS
// ---------------------------------
// Response: {
//   "accessToken": "eyJhbGc...",  // New JWT
//   "refreshToken": "yL0qM..."    // New refresh token
// }
//
// localStorage.setItem('accessToken', response.accessToken);
// localStorage.setItem('refreshToken', response.refreshToken);
//
// STEP 7: CLIENT RETRIES ORIGINAL REQUEST
// ----------------------------------------
// fetch('/api/auth', {
//   headers: { 'Authorization': `Bearer ${newAccessToken}` }
// })
//
// Server response: 200 OK ✓
//
// User never noticed anything! Seamless experience!
//
// ============================================================================
//
// ERROR SCENARIOS:
// ================
//
// 1. REFRESH TOKEN EXPIRED:
// -------------------------
// Request: {
//   userId: "123e...",
//   refreshToken: "xK9pL..."
// }
//
// Server check: user.RefreshTokenExpiryTime <= DateTime.UtcNow
// Result: Return 401 Unauthorized
// Client action: Redirect to login page
// User: Must log in again
//
// 2. INVALID REFRESH TOKEN:
// --------------------------
// Request: {
//   userId: "123e...",
//   refreshToken: "WRONG_TOKEN"
// }
//
// Server check: user.RefreshToken != "WRONG_TOKEN"
// Result: Return 401 Unauthorized
// Client action: Redirect to login page
// User: Must log in again
//
// 3. USER NOT FOUND:
// ------------------
// Request: {
//   userId: "INVALID_ID",
//   refreshToken: "xK9pL..."
// }
//
// Server check: user == null
// Result: Return 401 Unauthorized
// Client action: Redirect to login page
// User: Must log in again
//
// 4. USER LOGGED OUT:
// -------------------
// User clicked "Logout" → Server set user.RefreshToken = null
//
// Request: {
//   userId: "123e...",
//   refreshToken: "xK9pL..."  // Old token
// }
//
// Server check: user.RefreshToken (null) != "xK9pL..."
// Result: Return 401 Unauthorized
// Client action: Redirect to login page
// User: Must log in again
//
// ============================================================================

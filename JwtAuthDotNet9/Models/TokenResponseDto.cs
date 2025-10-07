// ============================================================================
// TOKEN RESPONSE DTO - DATA TRANSFER OBJECT FOR TOKEN RESPONSES
// ============================================================================
// PURPOSE: Return both access token and refresh token to the client
//
// WHEN USED:
// 1. After successful login
// 2. After successful token refresh
//
// WHY TWO TOKENS?
// This implements the "Dual Token" or "Refresh Token" pattern for security
//
// ACCESS TOKEN:
// - Short-lived (1 day)
// - Used for every API request
// - Contains user data (claims)
// - JWT format
//
// REFRESH TOKEN:
// - Long-lived (7 days)
// - Used to get new access token
// - Random string (no user data)
// - Stored in database
//
// FLOW EXAMPLE:
// Day 1: Login → Get both tokens
// Day 2: Access token expires
//        → Send refresh token to /api/auth/refresh-token
//        → Get NEW access token + NEW refresh token
// Day 3-7: Keep using new access tokens
// Day 8: Refresh token expires → Must login again
// ============================================================================

namespace JwtAuthDotNet9.Models
{
    public class TokenResponseDto
    {
        // ====================================================================
        // PROPERTY 1: ACCESS TOKEN (JWT)
        // ====================================================================
        // PURPOSE: Short-lived token for API authentication
        //
        // TYPE: string (JWT token)
        // EXAMPLE: "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiam9obiIsIm5hbWVpZCI6IjEyMyIsInJvbGUiOiJBZG1pbiJ9.Xy5JqK6F..."
        //
        // STRUCTURE: [HEADER].[PAYLOAD].[SIGNATURE]
        //
        // CONTAINS (Claims):
        // - Username
        // - User ID
        // - Role
        // - Expiration time
        // - Issuer
        // - Audience
        //
        // HOW CLIENT USES IT:
        // 1. Store in localStorage or cookie:
        //    localStorage.setItem('accessToken', token);
        //
        // 2. Send with every API request:
        //    fetch('/api/auth', {
        //      headers: {
        //        'Authorization': `Bearer ${accessToken}`
        //      }
        //    });
        //
        // 3. Server validates:
        //    - Checks signature (using secret key)
        //    - Checks expiration
        //    - Extracts user info from claims
        //
        // LIFETIME: 1 day (configured in AuthService.CreateToken)
        //
        // SECURITY:
        // - Can be decoded by anyone (Base64)
        // - But can't be modified without secret key
        // - Signature ensures integrity
        // - Short lifetime limits damage if stolen
        //
        // WHY "required"?
        // - C# 11 feature
        // - Must be set when creating object
        // - Prevents null access token
        // ====================================================================
        public required string AccessToken { get; set; }

        // ====================================================================
        // PROPERTY 2: REFRESH TOKEN
        // ====================================================================
        // PURPOSE: Long-lived token for getting new access tokens
        //
        // TYPE: string (random Base64 string)
        // EXAMPLE: "xK9pLm3nQ4r7sT8uV2wX5yZ6A1bC2dE3fG4hI5jK6="
        //
        // STRUCTURE: Random bytes converted to Base64
        // - NOT a JWT!
        // - Just a cryptographically secure random string
        // - 32 bytes = 256 bits of randomness
        //
        // HOW IT'S CREATED:
        // var randomBytes = new byte[32];
        // RandomNumberGenerator.Fill(randomBytes);
        // var refreshToken = Convert.ToBase64String(randomBytes);
        //
        // HOW CLIENT USES IT:
        // 1. Store alongside access token:
        //    localStorage.setItem('refreshToken', token);
        //    localStorage.setItem('userId', userId);
        //
        // 2. When access token expires (401 error):
        //    POST /api/auth/refresh-token
        //    Body: {
        //      userId: "123e4567-e89b-12d3-a456-426614174000",
        //      refreshToken: "xK9pL..."
        //    }
        //
        // 3. Server validates refresh token:
        //    - Finds user by userId
        //    - Checks if user.RefreshToken == provided token
        //    - Checks if user.RefreshTokenExpiryTime > now
        //    - If valid → Create NEW tokens
        //    - If invalid → Return 401 (user must login)
        //
        // LIFETIME: 7 days (configured in AuthService.GenerateAndSaveRefreshTokenAsync)
        //
        // SECURITY FEATURES:
        // 1. STORED IN DATABASE:
        //    - Can be revoked (set to null)
        //    - Can check if still valid
        //
        // 2. TOKEN ROTATION:
        //    - Each refresh creates NEW refresh token
        //    - Old token becomes invalid
        //    - Prevents replay attacks
        //
        // 3. ONE-TIME USE:
        //    - After using refresh token, it's replaced
        //    - If someone steals it, can only use once
        //    - Original owner will notice when their token stops working
        //
        // 4. EXPIRATION:
        //    - Even if stolen, only works for limited time
        //    - Forces re-login eventually
        //
        // WHY SEPARATE FROM ACCESS TOKEN?
        // - Access token sent with EVERY request (more exposure)
        // - Refresh token only sent when renewing (less exposure)
        // - If access token stolen, expires in 1 day
        // - More secure than long-lived access tokens
        // ====================================================================
        public required string RefreshToken { get; set; }
    }
}

// ============================================================================
// HOW THIS DTO IS USED IN PRACTICE
// ============================================================================
//
// LOGIN RESPONSE:
// ---------------
// Client: POST /api/auth/login
//         Body: { "username": "john", "password": "secret" }
//
// Server: 1. Validates credentials
//         2. Creates access token (JWT)
//         3. Creates refresh token (random string)
//         4. Saves refresh token to database
//         5. Returns TokenResponseDto:
//
// Response: {
//   "accessToken": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9...",
//   "refreshToken": "xK9pLm3nQ4r7sT8uV2wX5yZ6A1bC2dE3fG4hI5jK6="
// }
//
// Client: localStorage.setItem('accessToken', response.accessToken);
//         localStorage.setItem('refreshToken', response.refreshToken);
//
// ============================================================================
//
// AUTHENTICATED API REQUEST:
// --------------------------
// Client: GET /api/auth
//         Headers: { Authorization: "Bearer eyJhbGc..." }
//
// Server: 1. Authentication Middleware extracts token
//         2. Validates signature
//         3. Checks expiration
//         4. Extracts claims
//         5. If valid → Request proceeds
//         6. If expired → Returns 401
//
// ============================================================================
//
// TOKEN REFRESH FLOW:
// -------------------
// Scenario: Access token expired (it's been 1+ days)
//
// Client: Makes API request with expired access token
//
// Server: Returns 401 Unauthorized
//
// Client (Automatic): Detects 401 error
//         POST /api/auth/refresh-token
//         Body: {
//           userId: "123e4567...",
//           refreshToken: "xK9pL..."
//         }
//
// Server: 1. Finds user by userId
//         2. Checks if user.RefreshToken == "xK9pL..."
//         3. Checks if user.RefreshTokenExpiryTime > DateTime.UtcNow
//         4. If valid:
//            - Create NEW access token
//            - Create NEW refresh token
//            - Update database with new refresh token
//            - Return TokenResponseDto with new tokens
//
// Response: {
//   "accessToken": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9...",  // NEW
//   "refreshToken": "yL0qMn4oR5s8T9vW3xY6z7B8cD9eF0gH1iJ2kL3="   // NEW
// }
//
// Client: Updates stored tokens
//         localStorage.setItem('accessToken', response.accessToken);
//         localStorage.setItem('refreshToken', response.refreshToken);
//         Retries original API request with new access token
//
// ============================================================================
//
// AUTOMATIC REFRESH IMPLEMENTATION (Frontend Example):
// -----------------------------------------------------
//
// // Axios interceptor for automatic token refresh
// axios.interceptors.response.use(
//   response => response,
//   async error => {
//     if (error.response.status === 401) {
//       // Access token expired
//       const refreshToken = localStorage.getItem('refreshToken');
//       const userId = localStorage.getItem('userId');
//
//       try {
//         // Get new tokens
//         const response = await axios.post('/api/auth/refresh-token', {
//           userId,
//           refreshToken
//         });
//
//         // Store new tokens
//         localStorage.setItem('accessToken', response.data.accessToken);
//         localStorage.setItem('refreshToken', response.data.refreshToken);
//
//         // Retry original request with new token
//         error.config.headers.Authorization = `Bearer ${response.data.accessToken}`;
//         return axios.request(error.config);
//       } catch {
//         // Refresh failed, redirect to login
//         window.location.href = '/login';
//       }
//     }
//     return Promise.reject(error);
//   }
// );
//
// With this setup, token refresh is AUTOMATIC and INVISIBLE to the user!
//
// ============================================================================

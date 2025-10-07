// ============================================================================
// AUTH SERVICE - THE BUSINESS LOGIC LAYER
// ============================================================================
// This service contains ALL the authentication logic:
// - User registration (creating new accounts)
// - User login (validating credentials, creating tokens)
// - Token refresh (getting new tokens without re-login)
// - Token creation (JWT generation)
//
// WHY SEPARATE FROM CONTROLLER?
// - Controllers handle HTTP stuff (requests/responses)
// - Services handle business logic (validation, database, tokens)
// - This makes code testable and reusable
//
// FLOW: Controller → Service → Database
//       Database → Service → Controller
// ============================================================================

using JwtAuthDotNet9.Data;
using JwtAuthDotNet9.Entities;
using JwtAuthDotNet9.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JwtAuthDotNet9.Services
{
    // ========================================================================
    // PRIMARY CONSTRUCTOR (C# 12 Feature)
    // ========================================================================
    // Dependency Injection in action!
    // - context: Database access (UserDbContext)
    // - configuration: Access to appsettings.json
    //
    // HOW IT WORKS:
    // 1. .NET sees we need UserDbContext and IConfiguration
    // 2. Looks in Program.cs where we registered these services
    // 3. Creates instances and injects them automatically
    // ========================================================================
    public class AuthService(UserDbContext context, IConfiguration configuration) : IAuthService
    {
        // ====================================================================
        // PUBLIC METHOD 1: LOGIN
        // ====================================================================
        // PURPOSE: Validate user credentials and return JWT tokens
        // CALLED BY: AuthController.Login()
        //
        // PARAMETERS:
        // - request: Contains username and password from user
        //
        // RETURNS:
        // - TokenResponseDto: Contains access token + refresh token
        // - null: Login failed (wrong username or password)
        //
        // FLOW:
        // 1. Find user in database by username
        // 2. If user doesn't exist → return null
        // 3. Verify password hash matches
        // 4. If password wrong → return null
        // 5. Create and return tokens
        // ====================================================================
        public async Task<TokenResponseDto?> LoginAsync(UserDto request)
        {
            // ================================================================
            // STEP 1: FIND USER IN DATABASE
            // ================================================================
            // FirstOrDefaultAsync: Returns first matching user OR null
            // Why async? Database operations can take time, don't block the thread
            // ================================================================
            var user = await context.Users.FirstOrDefaultAsync(u => u.Username == request.Username);
            // SQL equivalent: SELECT * FROM Users WHERE Username = 'john' LIMIT 1

            // ================================================================
            // STEP 2: CHECK IF USER EXISTS
            // ================================================================
            if (user is null)
            {
                // User not found in database
                // Return null so controller can send "Invalid credentials" error
                return null;
            }

            // ================================================================
            // STEP 3: VERIFY PASSWORD
            // ================================================================
            // IMPORTANT: We NEVER store plain text passwords!
            // - Database has: user.PasswordHash = "$2a$11$..." (hashed)
            // - User sent: request.Password = "mypassword123" (plain text)
            //
            // PasswordHasher.VerifyHashedPassword:
            // 1. Takes the plain password
            // 2. Hashes it the same way
            // 3. Compares the hashes
            // 4. Returns Success or Failed
            //
            // WHY THIS WORKS:
            // Same input + same algorithm = same hash
            // "mypassword123" → always produces same hash
            // "wrongpassword" → produces different hash
            //
            // WHY WE CAN'T REVERSE IT:
            // Hash is one-way: password → hash (easy)
            // But: hash → password (impossible!)
            // ================================================================
            if (new PasswordHasher<User>().VerifyHashedPassword(user, user.PasswordHash, request.Password)
                == PasswordVerificationResult.Failed)
            {
                // Password is wrong
                // Return null so controller can send "Invalid credentials" error
                return null;
            }

            // ================================================================
            // STEP 4: CREDENTIALS VALID! CREATE TOKENS
            // ================================================================
            // User exists AND password is correct
            // Create both access token (for API calls) and refresh token (to get new access token)
            // ================================================================
            return await CreateTokenResponse(user);
        }

        // ====================================================================
        // PRIVATE HELPER METHOD: CREATE TOKEN RESPONSE
        // ====================================================================
        // PURPOSE: Create both access token and refresh token
        // CALLED BY: LoginAsync() and RefreshTokensAsync()
        //
        // WHY PRIVATE?
        // - Only used internally in this class
        // - Not part of the public interface (IAuthService)
        //
        // WHAT IT DOES:
        // 1. Creates JWT access token (short-lived, 1 day)
        // 2. Creates refresh token (long-lived, 7 days)
        // 3. Saves refresh token to database
        // 4. Returns both in a DTO
        // ====================================================================
        private async Task<TokenResponseDto> CreateTokenResponse(User? user)
        {
            return new TokenResponseDto
            {
                // Create JWT token with user claims
                AccessToken = CreateToken(user),

                // Generate random refresh token and save to database
                RefreshToken = await GenerateAndSaveRefreshTokenAsync(user)
            };
        }

        // ====================================================================
        // PUBLIC METHOD 2: REGISTER
        // ====================================================================
        // PURPOSE: Create a new user account
        // CALLED BY: AuthController.Register()
        //
        // PARAMETERS:
        // - request: Contains username and password
        //
        // RETURNS:
        // - User: The created user object
        // - null: Registration failed (username already exists)
        //
        // FLOW:
        // 1. Check if username already exists
        // 2. If exists → return null
        // 3. Hash the password
        // 4. Create user object
        // 5. Save to database
        // 6. Return user
        // ====================================================================
        public async Task<User?> RegisterAsync(UserDto request)
        {
            // ================================================================
            // STEP 1: CHECK IF USERNAME ALREADY EXISTS
            // ================================================================
            // AnyAsync: Returns true if ANY user has this username
            // Why check first? We don't want duplicate usernames!
            // ================================================================
            if (await context.Users.AnyAsync(u => u.Username == request.Username))
            {
                // Username already taken
                // Return null so controller can send "Username already exists" error
                return null;
            }

            // ================================================================
            // STEP 2: CREATE USER OBJECT
            // ================================================================
            // Start with empty user object
            var user = new User();

            // ================================================================
            // STEP 3: HASH THE PASSWORD
            // ================================================================
            // CRITICAL SECURITY POINT!
            // NEVER store passwords in plain text!
            //
            // PasswordHasher.HashPassword:
            // Input: "mypassword123"
            // Output: "$2a$11$K5hN.ZJFzNb/LV.fB5YM8.nJKlQ..."
            //
            // WHAT IS THIS?
            // - $2a$ → Algorithm version (BCrypt)
            // - 11$ → Cost factor (higher = more secure, slower)
            // - Rest → Salt + Hash
            //
            // SALT: Random data added to password before hashing
            // WHY? Prevents rainbow table attacks
            // Same password with different salt = different hash!
            // User A: "password123" → hash1
            // User B: "password123" → hash2 (different!)
            //
            // IF DATABASE GETS HACKED:
            // Hacker sees: "$2a$11$K5hN..." (useless gibberish)
            // Hacker can't log in as the user!
            // ================================================================
            var hashedPassword = new PasswordHasher<User>()
                .HashPassword(user, request.Password);

            // ================================================================
            // STEP 4: SET USER PROPERTIES
            // ================================================================
            user.Username = request.Username;
            user.PasswordHash = hashedPassword;
            // Note: user.Role will be set to default value "" (empty string)
            // In production, you might want to set it to "User" by default

            // ================================================================
            // STEP 5: SAVE TO DATABASE
            // ================================================================
            context.Users.Add(user);  // Tell EF Core: "I want to add this"
            await context.SaveChangesAsync();  // Actually execute: INSERT INTO Users...
            // After SaveChanges, user.Id will be populated with the database-generated ID
            // ================================================================

            return user;
        }

        // ====================================================================
        // PUBLIC METHOD 3: REFRESH TOKENS
        // ====================================================================
        // PURPOSE: Get new tokens when access token expires
        // CALLED BY: AuthController.RefreshToken()
        //
        // WHY DO WE NEED THIS?
        // - Access tokens expire after 1 day (security)
        // - Instead of forcing user to login again, use refresh token
        // - Refresh token is long-lived (7 days)
        //
        // PARAMETERS:
        // - request: Contains userId and refreshToken
        //
        // RETURNS:
        // - TokenResponseDto: New access token + new refresh token
        // - null: Refresh failed (invalid/expired refresh token)
        //
        // FLOW:
        // 1. Validate refresh token (exists, not expired, matches user)
        // 2. If invalid → return null
        // 3. Create new tokens
        // 4. Return new tokens
        //
        // SECURITY NOTE: Why create NEW refresh token?
        // This is called "Refresh Token Rotation"
        // - Old refresh token becomes invalid
        // - If someone steals old token, they can't use it
        // - More secure than reusing same refresh token
        // ====================================================================
        public async Task<TokenResponseDto?> RefreshTokensAsync(RefreshTokenRequestDto request)
        {
            // Validate the refresh token
            var user = await ValidateRefreshTokenAsync(request.UserId, request.RefreshToken);

            if (user is null)
                return null;  // Invalid refresh token

            // Create new access token + new refresh token
            return await CreateTokenResponse(user);
        }

        // ====================================================================
        // PRIVATE HELPER METHOD: VALIDATE REFRESH TOKEN
        // ====================================================================
        // PURPOSE: Check if refresh token is valid
        //
        // CHECKS:
        // 1. User exists in database
        // 2. Refresh token matches what's stored in database
        // 3. Refresh token is not expired
        //
        // WHY STORE REFRESH TOKEN IN DATABASE?
        // - Access tokens are stateless (not stored anywhere)
        // - Refresh tokens are stateful (stored in database)
        // - This allows us to revoke refresh tokens (set to null in DB)
        // - If user logs out, we can delete their refresh token
        // ====================================================================
        private async Task<User?> ValidateRefreshTokenAsync(Guid userId, string refreshToken)
        {
            // Find user by ID
            var user = await context.Users.FindAsync(userId);
            // FindAsync is optimized for primary key lookups

            // Check all validation conditions
            if (user is null                                          // User doesn't exist
                || user.RefreshToken != refreshToken                   // Token doesn't match
                || user.RefreshTokenExpiryTime <= DateTime.UtcNow)    // Token expired
            {
                return null;  // Validation failed
            }

            return user;  // Valid!
        }

        // ====================================================================
        // PRIVATE HELPER METHOD: GENERATE REFRESH TOKEN
        // ====================================================================
        // PURPOSE: Create a cryptographically secure random string
        //
        // WHY NOT JUST USE Guid.NewGuid()?
        // - GUIDs are unique but not cryptographically secure
        // - RandomNumberGenerator uses OS-level randomness
        // - Much harder to predict/guess
        //
        // WHAT IT CREATES:
        // - 32 random bytes
        // - Converted to Base64 string
        // - Result looks like: "xK9pLm3nQ4r7sT8uV2wX5yZ6..."
        //
        // LENGTH:
        // - 32 bytes = 256 bits of randomness
        // - Base64 encoding → ~44 characters
        // ====================================================================
        private string GenerateRefreshToken()
        {
            // Create array to hold random bytes
            var randomNumber = new byte[32];

            // Get cryptographically secure random number generator
            using var rng = RandomNumberGenerator.Create();

            // Fill array with random bytes
            rng.GetBytes(randomNumber);

            // Convert bytes to Base64 string (readable format)
            return Convert.ToBase64String(randomNumber);
            // Example output: "xK9pLm3nQ4r7sT8uV2wX5yZ6A1bC2dE3fG4hI5jK6="
        }

        // ====================================================================
        // PRIVATE HELPER METHOD: GENERATE AND SAVE REFRESH TOKEN
        // ====================================================================
        // PURPOSE: Create refresh token and save it to database
        //
        // FLOW:
        // 1. Generate random refresh token string
        // 2. Update user record with new token
        // 3. Set expiration time (7 days from now)
        // 4. Save to database
        // 5. Return token string
        //
        // WHY SAVE TO DATABASE?
        // - So we can validate it later (in ValidateRefreshTokenAsync)
        // - So we can revoke it (set to null when user logs out)
        // ====================================================================
        private async Task<string> GenerateAndSaveRefreshTokenAsync(User user)
        {
            // Generate cryptographically secure random token
            var refreshToken = GenerateRefreshToken();

            // Update user object
            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);
            // UtcNow = Universal Time Coordinated (not affected by timezones)

            // Save to database
            await context.SaveChangesAsync();
            // SQL equivalent: UPDATE Users SET RefreshToken=..., RefreshTokenExpiryTime=... WHERE Id=...

            return refreshToken;
        }

        // ====================================================================
        // PRIVATE HELPER METHOD: CREATE JWT TOKEN (THE CORE OF JWT AUTH!)
        // ====================================================================
        // PURPOSE: Create a JWT access token
        // This is THE MOST IMPORTANT METHOD in the entire auth system!
        //
        // WHAT IS A JWT TOKEN?
        // A string with 3 parts separated by dots:
        // [HEADER].[PAYLOAD].[SIGNATURE]
        //
        // EXAMPLE:
        // eyJhbGc...  .  eyJuYW1l...  .  SflKxwRJ...
        //   Header         Payload        Signature
        //
        // FLOW:
        // 1. Create claims (user data to put in token)
        // 2. Get secret key from configuration
        // 3. Create signing credentials
        // 4. Create token descriptor
        // 5. Generate token string
        // ====================================================================
        private string CreateToken(User user)
        {
            // ================================================================
            // STEP 1: CREATE CLAIMS
            // ================================================================
            // Claims = Pieces of information about the user
            // These get embedded in the JWT token payload
            //
            // IMPORTANT: Anyone can decode and READ these claims!
            // They're NOT encrypted, just Base64 encoded
            // So NEVER put sensitive data here (passwords, credit cards, etc.)
            //
            // CLAIM TYPES:
            // - ClaimTypes.Name: User's username
            // - ClaimTypes.NameIdentifier: User's unique ID
            // - ClaimTypes.Role: User's role (for authorization)
            //
            // WHY PUT DATA IN TOKEN?
            // So we don't need to query the database on every request!
            // Token contains: userId, username, role
            // Server validates token → extracts claims → knows who user is
            // No database query needed!
            // ================================================================
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Username),
                // Used in controllers: User.Identity.Name

                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                // Used in controllers: User.FindFirst(ClaimTypes.NameIdentifier)?.Value

                new Claim(ClaimTypes.Role, user.Role)
                // Used in [Authorize(Roles = "Admin")]
            };

            // ================================================================
            // STEP 2: GET SECRET KEY
            // ================================================================
            // This is THE MOST IMPORTANT SECURITY COMPONENT!
            //
            // SECRET KEY:
            // - Stored in appsettings.json
            // - ONLY the server knows this
            // - Used to sign the token
            // - Used to verify the token
            //
            // IF THIS LEAKS:
            // - Anyone can create valid tokens
            // - Anyone can impersonate any user
            // - Your entire auth system is compromised!
            //
            // PROTECTION:
            // - NEVER commit to Git
            // - Use environment variables in production
            // - Use Azure Key Vault or AWS Secrets Manager
            // - Rotate periodically
            // ================================================================
            var key = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(configuration.GetValue<string>("AppSettings:Token")!));
            // SymmetricSecurityKey: Same key for signing and verifying
            // (vs AsymmetricSecurityKey: Different keys for signing/verifying)

            // ================================================================
            // STEP 3: CREATE SIGNING CREDENTIALS
            // ================================================================
            // Signing credentials = Key + Algorithm
            //
            // ALGORITHM: HmacSha512
            // - HMAC = Hash-based Message Authentication Code
            // - SHA512 = Secure Hash Algorithm 512-bit
            // - One of the most secure algorithms available
            //
            // HOW IT WORKS:
            // 1. Take header + payload
            // 2. Combine with secret key
            // 3. Run through HMAC-SHA512 algorithm
            // 4. Result = Signature
            //
            // METAPHOR: Wax seal on a letter
            // - Letter = Header + Payload
            // - King's ring = Secret key
            // - Wax seal = Signature
            // - Anyone can read letter, but can't fake seal!
            // ================================================================
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512);

            // ================================================================
            // STEP 4: CREATE JWT TOKEN DESCRIPTOR
            // ================================================================
            // This defines ALL properties of the token
            // ================================================================
            var tokenDescriptor = new JwtSecurityToken(
                // Issuer: Who created this token?
                // Must match ValidIssuer in Program.cs
                issuer: configuration.GetValue<string>("AppSettings:Issuer"),

                // Audience: Who is this token for?
                // Must match ValidAudience in Program.cs
                audience: configuration.GetValue<string>("AppSettings:Audience"),

                // Claims: User data embedded in token
                claims: claims,

                // Expiration: When does this token become invalid?
                // After this time, token is rejected automatically
                // Setting: 1 day from now
                expires: DateTime.UtcNow.AddDays(1),

                // Signing credentials: How to sign this token
                signingCredentials: creds
            );

            // ================================================================
            // STEP 5: GENERATE TOKEN STRING
            // ================================================================
            // JwtSecurityTokenHandler converts the token object to a string
            //
            // RESULT:
            // "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiam9obiIsIm5hbWVpZCI6IjEyMyIsInJvbGUiOiJBZG1pbiIsIm5iZiI6MTcwOTgzMjAwMCwiZXhwIjoxNzA5OTE4NDAwLCJpYXQiOjE3MDk4MzIwMDAsImlzcyI6Ik15QXdlc29tZUFwcCIsImF1ZCI6Ik15QXdlc29tZUF1ZGllbmNlIn0.Xy5JqK6F8hKN0g5nqkY5JNF8hK6F8hKN0g5nqkY5JNF"
            //
            // STRUCTURE:
            // Part 1 (Header): eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9
            // Part 2 (Payload): eyJuYW1lIjoiam9obiIsIm5hbWVpZCI6IjEyMyI...
            // Part 3 (Signature): Xy5JqK6F8hKN0g5nqkY5JNF8hK6F8hKN0g5nqkY5JNF
            //
            // This string is sent to the browser, stored, and sent back
            // with every API request in the Authorization header!
            // ================================================================
            return new JwtSecurityTokenHandler().WriteToken(tokenDescriptor);
        }
    }
}

// ============================================================================
// SUMMARY: HOW EVERYTHING CONNECTS
// ============================================================================
//
// REGISTRATION FLOW:
// ------------------
// Browser → POST /api/auth/register → AuthController.Register()
//   → AuthService.RegisterAsync()
//     → Check if username exists
//     → Hash password
//     → Save user to database
//   → Return user object
// → Browser receives user data
//
// LOGIN FLOW:
// -----------
// Browser → POST /api/auth/login → AuthController.Login()
//   → AuthService.LoginAsync()
//     → Find user in database
//     → Verify password hash
//     → CreateTokenResponse()
//       → CreateToken() - Creates JWT access token
//       → GenerateAndSaveRefreshTokenAsync() - Creates refresh token
//     → Return TokenResponseDto
//   → Return tokens
// → Browser stores tokens (localStorage/cookie)
//
// AUTHENTICATED REQUEST FLOW:
// ---------------------------
// Browser → GET /api/auth (with JWT in header)
//   → Authentication Middleware (Program.cs)
//     → Extract token from Authorization header
//     → Validate signature using secret key
//     → Verify issuer, audience, expiration
//     → Extract claims from token payload
//     → Populate User object with claims
//   → AuthController.AuthenticatedOnlyEndpoint()
//     → Can access User.Identity.Name, User.Claims, etc.
//     → Return response
//   → Browser receives response
//
// TOKEN REFRESH FLOW:
// -------------------
// Browser → POST /api/auth/refresh-token → AuthController.RefreshToken()
//   → AuthService.RefreshTokensAsync()
//     → ValidateRefreshTokenAsync()
//       → Find user by ID
//       → Check token matches database
//       → Check not expired
//     → CreateTokenResponse()
//       → Create new access token
//       → Create new refresh token
//       → Save new refresh token to database
//     → Return new tokens
//   → Return tokens
// → Browser updates stored tokens
//
// ============================================================================

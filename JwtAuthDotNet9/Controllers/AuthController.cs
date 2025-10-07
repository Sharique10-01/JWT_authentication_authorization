// ============================================================================
// AUTH CONTROLLER - THE ENTRY POINT FOR ALL AUTHENTICATION REQUESTS
// ============================================================================
// This controller handles ALL authentication-related HTTP requests:
// - Register new users
// - Login (get JWT tokens)
// - Refresh expired tokens
// - Test authentication/authorization
//
// FLOW: Browser/Client → HTTP Request → This Controller → AuthService → Database
//       Database → AuthService → Controller → HTTP Response → Browser/Client
//
// URL PATTERN: All endpoints start with /api/auth/
// Example: POST https://localhost:5001/api/auth/login
// ============================================================================

using JwtAuthDotNet9.Entities;
using JwtAuthDotNet9.Models;
using JwtAuthDotNet9.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JwtAuthDotNet9.Controllers
{
    // ========================================================================
    // CONTROLLER ATTRIBUTES (Metadata)
    // ========================================================================
    [Route("api/[controller]")]  // [controller] = "Auth" → /api/auth
    [ApiController]               // Marks this as an API controller (enables automatic model validation)
    // ========================================================================

    public class AuthController(IAuthService authService) : ControllerBase
    // ========================================================================
    // PRIMARY CONSTRUCTOR (New C# 12 Feature!)
    // ========================================================================
    // Old way:
    //   private readonly IAuthService _authService;
    //   public AuthController(IAuthService authService) { _authService = authService; }
    //
    // New way (above):
    //   public AuthController(IAuthService authService)
    //
    // WHAT: Automatically creates a field and assigns the parameter
    // WHY: Less boilerplate code, cleaner syntax
    // HOW IT WORKS:
    //   1. .NET sees we need IAuthService
    //   2. Looks in Program.cs for: builder.Services.AddScoped<IAuthService, AuthService>()
    //   3. Creates AuthService instance
    //   4. Injects it here
    // ========================================================================
    {
        // ====================================================================
        // ENDPOINT 1: REGISTER NEW USER
        // ====================================================================
        // URL: POST /api/auth/register
        // PURPOSE: Create a new user account
        //
        // REQUEST BODY (JSON):
        // {
        //   "username": "john@example.com",
        //   "password": "mypassword123"
        // }
        //
        // FLOW:
        // 1. User fills registration form in browser
        // 2. JavaScript sends POST request with username/password
        // 3. .NET routes request to this method
        // 4. [FromBody] automatically converts JSON to UserDto object
        // 5. Calls authService.RegisterAsync()
        // 6. Returns response to browser
        //
        // RESPONSES:
        // - 200 OK + User object → Registration successful
        // - 400 Bad Request → Username already exists
        // ====================================================================
        [HttpPost("register")]  // Handles POST /api/auth/register
        public async Task<ActionResult<User>> Register([FromBody] UserDto request)
        // Why async Task? Because we need to wait for database operations
        // Why ActionResult<User>? So we can return either User or error
        // Why [FromBody]? Tells .NET to read data from HTTP request body
        {
            // Call AuthService to handle business logic
            var user = await authService.RegisterAsync(request);
            // await = "wait for this to complete before continuing"

            // Check if registration failed
            if (user is null)  // null means username already exists
                return BadRequest("Username already exists.");
            // BadRequest = HTTP 400 status code

            // Success! Return the created user
            return Ok(user);
            // Ok = HTTP 200 status code
            // Browser receives: { "id": "...", "username": "john", ... }
        }

        // ====================================================================
        // ENDPOINT 2: LOGIN (MOST IMPORTANT!)
        // ====================================================================
        // URL: POST /api/auth/login
        // PURPOSE: Authenticate user and return JWT tokens
        //
        // REQUEST BODY (JSON):
        // {
        //   "username": "john@example.com",
        //   "password": "mypassword123"
        // }
        //
        // FLOW:
        // 1. User enters username/password in login form
        // 2. JavaScript sends POST request
        // 3. This method receives the request
        // 4. Calls authService.LoginAsync() which:
        //    a. Finds user in database
        //    b. Verifies password hash
        //    c. Creates JWT access token (short-lived, 1 day)
        //    d. Creates refresh token (long-lived, 7 days)
        // 5. Returns both tokens to browser
        // 6. Browser stores tokens (localStorage or cookie)
        //
        // RESPONSE (SUCCESS):
        // {
        //   "accessToken": "eyJhbGc...",  ← Use this for API requests
        //   "refreshToken": "xK9pL..."     ← Use this to get new access token
        // }
        //
        // RESPONSES:
        // - 200 OK + tokens → Login successful
        // - 400 Bad Request → Invalid credentials
        // ====================================================================
        [HttpPost("login")]  // Handles POST /api/auth/login
        public async Task<ActionResult<TokenResponseDto>> Login([FromBody] UserDto request)
        {
            // Call AuthService to validate credentials and create tokens
            var result = await authService.LoginAsync(request);

            // Check if login failed
            if (result is null)  // null means wrong username or password
                return BadRequest("Invalid username or password.");
            // SECURITY NOTE: We don't say which one is wrong (username vs password)
            // to prevent attackers from knowing if a username exists

            // Success! Return tokens
            return Ok(result);
            // Browser now has:
            // - accessToken: Use for API requests (expires in 1 day)
            // - refreshToken: Use to get new access token (expires in 7 days)
        }

        // ====================================================================
        // ENDPOINT 3: REFRESH TOKEN
        // ====================================================================
        // URL: POST /api/auth/refresh-token
        // PURPOSE: Get new access token when old one expires
        //
        // WHY NEEDED?
        // Access tokens expire after 1 day for security.
        // Instead of forcing user to login again, we use refresh token
        // to get a new access token.
        //
        // REQUEST BODY (JSON):
        // {
        //   "userId": "123e4567-e89b-12d3-a456-426614174000",
        //   "refreshToken": "xK9pL..."
        // }
        //
        // FLOW:
        // 1. User makes API request with access token
        // 2. API returns 401 Unauthorized (token expired)
        // 3. JavaScript automatically calls this endpoint with refresh token
        // 4. This method validates refresh token
        // 5. Returns NEW access token + NEW refresh token
        // 6. JavaScript retries original request with new access token
        //
        // TYPICAL SCENARIO:
        // Day 1: User logs in → Gets tokens
        // Day 2: Access token still valid → Everything works
        // Day 3: Access token expires → Auto-refresh → Everything still works
        // Day 8: Refresh token expires → User must login again
        //
        // RESPONSES:
        // - 200 OK + new tokens → Refresh successful
        // - 401 Unauthorized → Refresh token invalid/expired (user must login)
        // ====================================================================
        [HttpPost("refresh-token")]  // Handles POST /api/auth/refresh-token
        public async Task<ActionResult<TokenResponseDto>> RefreshToken([FromBody] RefreshTokenRequestDto request)
        {
            // Call AuthService to validate refresh token and create new tokens
            var result = await authService.RefreshTokensAsync(request);

            // Check if refresh failed
            if (result is null || result.AccessToken is null || result.RefreshToken is null)
                return Unauthorized("Invalid refresh token.");
            // Unauthorized = HTTP 401 status code
            // This tells the client: "Your refresh token is invalid, please login again"

            // Success! Return new tokens
            return Ok(result);
        }

        // ====================================================================
        // ENDPOINT 4: AUTHENTICATED ONLY TEST ENDPOINT
        // ====================================================================
        // URL: GET /api/auth
        // PURPOSE: Test if user is authenticated (has valid JWT)
        //
        // AUTHORIZATION: [Authorize] - Requires valid JWT token
        //
        // HOW TO CALL:
        // GET /api/auth
        // Headers: {
        //   "Authorization": "Bearer eyJhbGc..."
        // }
        //
        // FLOW:
        // 1. Browser sends GET request with JWT token in header
        // 2. .NET Authentication Middleware intercepts request
        // 3. Validates token (signature, expiration, issuer, audience)
        // 4. If valid → Request reaches this method
        // 5. If invalid → Returns 401 Unauthorized (doesn't reach this method)
        //
        // RESPONSES:
        // - 200 OK + message → User is authenticated
        // - 401 Unauthorized → Token missing/invalid/expired
        // ====================================================================
        [Authorize]  // 🔒 Requires valid JWT token
        [HttpGet]    // Handles GET /api/auth
        public IActionResult AuthenticatedOnlyEndpoint()
        // Note: Not async because we're not doing any database/IO operations
        {
            // If we reached here, user is authenticated!
            // The [Authorize] attribute already validated the JWT token

            // You can access user info from the JWT claims:
            // var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            // var username = User.FindFirst(ClaimTypes.Name)?.Value;
            // var role = User.FindFirst(ClaimTypes.Role)?.Value;

            return Ok("You are authenticated!");
        }

        // ====================================================================
        // ENDPOINT 5: ADMIN ONLY TEST ENDPOINT
        // ====================================================================
        // URL: GET /api/auth/admin-only
        // PURPOSE: Test role-based authorization
        //
        // AUTHORIZATION: [Authorize(Roles = "Admin")] - Requires Admin role
        //
        // HOW TO CALL:
        // GET /api/auth/admin-only
        // Headers: {
        //   "Authorization": "Bearer eyJhbGc..."
        // }
        //
        // FLOW:
        // 1. Browser sends GET request with JWT token in header
        // 2. Authentication Middleware validates token (same as above)
        // 3. Authorization Middleware checks if user has "Admin" role
        //    - Looks at the "role" claim in the JWT token
        //    - Token contains: { "role": "Admin" }
        // 4. If role matches → Request reaches this method
        // 5. If role doesn't match → Returns 403 Forbidden
        //
        // RESPONSES:
        // - 200 OK + message → User is Admin
        // - 401 Unauthorized → Token missing/invalid/expired
        // - 403 Forbidden → User authenticated but not an Admin
        //
        // DIFFERENCE BETWEEN 401 AND 403:
        // - 401 Unauthorized: "I don't know who you are" (no/invalid token)
        // - 403 Forbidden: "I know who you are, but you can't do this" (valid token, wrong role)
        // ====================================================================
        [Authorize(Roles = "Admin")]  // 🔒🔒 Requires valid JWT + Admin role
        [HttpGet("admin-only")]       // Handles GET /api/auth/admin-only
        public IActionResult AdminOnlyEndpoint()
        {
            // If we reached here, user is authenticated AND is an Admin!

            return Ok("You are an admin!");
            // Note: There's a typo in the message ("and" should be "an")
        }
    }
}

// ============================================================================
// SUMMARY: REQUEST FLOW VISUALIZATION
// ============================================================================
//
// EXAMPLE: User logs in
// ----------------------
// 1. Browser:
//    POST /api/auth/login
//    Body: { "username": "john", "password": "secret" }
//
// 2. .NET Routing:
//    "POST to /api/auth/login → AuthController.Login()"
//
// 3. AuthController.Login():
//    - Receives UserDto request
//    - Calls authService.LoginAsync(request)
//
// 4. AuthService:
//    - Checks database for user
//    - Verifies password
//    - Creates JWT tokens
//    - Returns TokenResponseDto
//
// 5. AuthController.Login():
//    - Receives result from service
//    - Returns Ok(result) → HTTP 200
//
// 6. Browser:
//    Receives: { "accessToken": "...", "refreshToken": "..." }
//    Stores tokens for future requests
//
// ============================================================================
//
// EXAMPLE: User accesses protected endpoint
// ------------------------------------------
// 1. Browser:
//    GET /api/auth/admin-only
//    Headers: { "Authorization": "Bearer eyJhbGc..." }
//
// 2. Authentication Middleware (configured in Program.cs):
//    - Extracts token from Authorization header
//    - Validates signature using secret key
//    - Checks expiration
//    - Extracts claims (userId, username, role)
//    - Populates User object
//
// 3. Authorization Middleware:
//    - Checks [Authorize(Roles = "Admin")]
//    - Looks at User.Claims for role
//    - If role == "Admin" → Continue
//    - If role != "Admin" → Return 403 Forbidden
//
// 4. AuthController.AdminOnlyEndpoint():
//    - Method executes
//    - Returns Ok("You are an admin!")
//
// 5. Browser:
//    Receives: "You are an admin!"
//
// ============================================================================

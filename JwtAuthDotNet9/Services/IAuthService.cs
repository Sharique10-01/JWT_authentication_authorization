// ============================================================================
// IAUTH SERVICE INTERFACE - THE CONTRACT
// ============================================================================
// This is an INTERFACE, which defines a CONTRACT.
// Think of it as a "job description" - it lists what methods must exist,
// but doesn't implement them.
//
// WHY USE INTERFACES?
// 1. ABSTRACTION: Controllers don't need to know HOW things work, just WHAT they can do
// 2. DEPENDENCY INJECTION: Program.cs maps IAuthService → AuthService
// 3. TESTABILITY: Can create mock implementations for testing
// 4. FLEXIBILITY: Can swap implementations without changing controllers
//
// EXAMPLE:
// Controller says: "I need something that implements IAuthService"
// .NET says: "Here's AuthService, it implements IAuthService"
// Controller uses it without knowing it's specifically AuthService
//
// ANALOGY:
// Interface = "I need a vehicle with 4 wheels that can move"
// Implementation = Could be a car, truck, or van - doesn't matter!
// ============================================================================

using JwtAuthDotNet9.Entities;
using JwtAuthDotNet9.Models;

namespace JwtAuthDotNet9.Services
{
    // ========================================================================
    // INTERFACE DEFINITION
    // ========================================================================
    // "public interface" means anyone can use this contract
    // "IAuthService" - naming convention: interfaces start with "I"
    // ========================================================================
    public interface IAuthService
    {
        // ====================================================================
        // METHOD 1: REGISTER USER
        // ====================================================================
        // PURPOSE: Create a new user account
        //
        // PARAMETERS:
        // - UserDto request: Contains username and password from registration form
        //
        // RETURNS:
        // - Task<User?>: Async operation that returns:
        //   - User object if registration succeeds
        //   - null if username already exists
        //
        // WHY Task<>?
        // - Task means this is an async method (doesn't block while waiting)
        // - Useful for database operations which can take time
        //
        // WHY nullable (User?)?
        // - "?" means it can return null
        // - null indicates failure (username taken)
        // - Allows caller to handle success vs failure
        //
        // FLOW:
        // 1. Controller receives registration request
        // 2. Controller calls: await authService.RegisterAsync(request)
        // 3. Implementation (AuthService) does the work
        // 4. Returns User or null
        // ====================================================================
        Task<User?> RegisterAsync(UserDto request);

        // ====================================================================
        // METHOD 2: LOGIN USER
        // ====================================================================
        // PURPOSE: Validate credentials and create JWT tokens
        //
        // PARAMETERS:
        // - UserDto request: Contains username and password from login form
        //
        // RETURNS:
        // - Task<TokenResponseDto?>: Async operation that returns:
        //   - TokenResponseDto (access token + refresh token) if login succeeds
        //   - null if credentials are invalid
        //
        // WHY TokenResponseDto?
        // - Need to return TWO things: access token AND refresh token
        // - DTO (Data Transfer Object) groups them together
        //
        // WHY nullable (TokenResponseDto?)?
        // - null indicates login failure (wrong username/password)
        // - Allows controller to send appropriate error message
        //
        // FLOW:
        // 1. Controller receives login request
        // 2. Controller calls: await authService.LoginAsync(request)
        // 3. Implementation validates user and creates tokens
        // 4. Returns tokens or null
        // ====================================================================
        Task<TokenResponseDto?> LoginAsync(UserDto request);

        // ====================================================================
        // METHOD 3: REFRESH TOKENS
        // ====================================================================
        // PURPOSE: Get new tokens when access token expires
        //
        // PARAMETERS:
        // - RefreshTokenRequestDto request: Contains userId and refreshToken
        //
        // RETURNS:
        // - Task<TokenResponseDto?>: Async operation that returns:
        //   - TokenResponseDto (new access token + new refresh token) if valid
        //   - null if refresh token is invalid or expired
        //
        // WHY NEEDED?
        // - Access tokens expire quickly (1 day) for security
        // - Refresh tokens last longer (7 days)
        // - User stays logged in without re-entering password
        //
        // FLOW:
        // 1. Access token expires
        // 2. Client sends refresh token to get new access token
        // 3. Controller calls: await authService.RefreshTokensAsync(request)
        // 4. Implementation validates refresh token and creates new tokens
        // 5. Returns new tokens or null
        //
        // SECURITY:
        // - Old refresh token is replaced (refresh token rotation)
        // - Prevents stolen tokens from being reused
        // ====================================================================
        Task<TokenResponseDto?> RefreshTokensAsync(RefreshTokenRequestDto request);
    }
}

// ============================================================================
// HOW INTERFACES WORK WITH DEPENDENCY INJECTION
// ============================================================================
//
// STEP 1: DEFINE INTERFACE (this file)
// --------------------------------------
// public interface IAuthService {
//     Task<User?> RegisterAsync(UserDto request);
// }
//
// STEP 2: IMPLEMENT INTERFACE (AuthService.cs)
// ---------------------------------------------
// public class AuthService : IAuthService {
//     public async Task<User?> RegisterAsync(UserDto request) {
//         // Actual implementation here
//     }
// }
//
// STEP 3: REGISTER IN DI CONTAINER (Program.cs)
// ----------------------------------------------
// builder.Services.AddScoped<IAuthService, AuthService>();
// Translation: "When someone asks for IAuthService, give them AuthService"
//
// STEP 4: USE IN CONTROLLER (AuthController.cs)
// ----------------------------------------------
// public class AuthController(IAuthService authService) {
//     // .NET automatically injects AuthService here
//     // Controller only knows about IAuthService interface
//     // Doesn't know or care that it's specifically AuthService
// }
//
// ============================================================================
//
// WHY THIS PATTERN?
// -----------------
// 1. LOOSE COUPLING:
//    - Controller depends on interface, not concrete class
//    - Can change implementation without touching controller
//
// 2. TESTABILITY:
//    - Can create FakeAuthService for testing
//    - Controller doesn't know the difference
//
//    Example test:
//    public class FakeAuthService : IAuthService {
//        public Task<User?> RegisterAsync(UserDto request) {
//            return Task.FromResult(new User { Username = "test" });
//        }
//    }
//
// 3. MULTIPLE IMPLEMENTATIONS:
//    - Could have: DatabaseAuthService, LdapAuthService, OAuthService
//    - All implement IAuthService
//    - Swap them by changing one line in Program.cs
//
// 4. CLEAR CONTRACT:
//    - Interface shows exactly what auth system can do
//    - Documentation at a glance
//    - No implementation details to confuse you
//
// ============================================================================

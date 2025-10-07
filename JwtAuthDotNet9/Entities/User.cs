// ============================================================================
// USER ENTITY - DATABASE TABLE REPRESENTATION
// ============================================================================
// This class represents a USER in the database.
// Think of it as the "blueprint" for the Users table.
//
// WHAT IS AN ENTITY?
// - Entity = A class that maps to a database table
// - Each property = A column in the table
// - Each instance (object) = A row in the table
//
// EXAMPLE IN DATABASE:
// Users Table:
// +--------------------------------------+----------+---------------+-------+---------------+----------------------+
// | Id                                   | Username | PasswordHash  | Role  | RefreshToken  | RefreshTokenExpiry   |
// +--------------------------------------+----------+---------------+-------+---------------+----------------------+
// | 123e4567-e89b-12d3-a456-426614174000 | john     | $2a$11$...   | Admin | xK9pL...      | 2024-01-15 10:30:00  |
// | 234e5678-e89b-12d3-a456-426614174001 | mary     | $2a$11$...   | User  | yL0qM...      | 2024-01-16 14:20:00  |
// +--------------------------------------+----------+---------------+-------+---------------+----------------------+
//
// ENTITY FRAMEWORK CORE (EF Core) MAGIC:
// - Automatically creates this table (via migrations)
// - Converts C# objects to SQL queries
// - Converts SQL results back to C# objects
//
// EXAMPLE:
// C#: var user = new User { Username = "john" };
// EF Core SQL: INSERT INTO Users (Username) VALUES ('john')
// ============================================================================

namespace JwtAuthDotNet9.Entities
{
    public class User
    {
        // ====================================================================
        // PROPERTY 1: ID (PRIMARY KEY)
        // ====================================================================
        // PURPOSE: Uniquely identify each user
        //
        // TYPE: Guid (Globally Unique Identifier)
        // - Looks like: 123e4567-e89b-12d3-a456-426614174000
        // - 128-bit number (very very large!)
        // - Virtually impossible to have duplicates
        //
        // WHY GUID INSTEAD OF INT?
        // INT:
        //   - Sequential: 1, 2, 3, 4...
        //   - Predictable (security risk: attacker can guess user IDs)
        //   - Easy to enumerate all users
        //
        // GUID:
        //   - Random: 123e4567-e89b-12d3-a456-426614174000
        //   - Impossible to guess next ID
        //   - Can't enumerate all users
        //   - Better for distributed systems (no ID collision)
        //
        // EF CORE BEHAVIOR:
        // - "Id" property is automatically detected as primary key
        // - Database generates value automatically on insert
        // ====================================================================
        public Guid Id { get; set; }

        // ====================================================================
        // PROPERTY 2: USERNAME
        // ====================================================================
        // PURPOSE: User's login identifier (email, username, etc.)
        //
        // TYPE: string
        // DEFAULT: string.Empty (prevents null issues)
        //
        // WHY string.Empty?
        // - New C# feature: prevents null reference errors
        // - Without it: Username could be null → potential crashes
        // - With it: Username is never null, at worst it's ""
        //
        // TYPICAL VALUES:
        // - Email: "john@example.com"
        // - Username: "john123"
        //
        // UNIQUENESS:
        // - Should be unique! (enforced in AuthService.RegisterAsync)
        // - No two users should have the same username
        // - Could add [Index(IsUnique = true)] attribute for DB constraint
        //
        // SECURITY NOTE:
        // - This is NOT secret data
        // - Safe to put in JWT token
        // - Safe to return in API responses
        // ====================================================================
        public string Username { get; set; } = string.Empty;

        // ====================================================================
        // PROPERTY 3: PASSWORD HASH
        // ====================================================================
        // PURPOSE: Stores hashed (encrypted) password
        //
        // TYPE: string
        // EXAMPLE VALUE: "$2a$11$K5hN.ZJFzNb/LV.fB5YM8.nJKlQjnW9Zg8Yq..."
        //
        // CRITICAL SECURITY CONCEPT:
        // ❌ NEVER STORE PLAIN TEXT PASSWORDS!
        // ✅ ALWAYS STORE HASHED PASSWORDS!
        //
        // WHAT IS HASHING?
        // - One-way encryption
        // - Password → Hash (easy)
        // - Hash → Password (impossible!)
        //
        // EXAMPLE:
        // Password: "mypassword123"
        // Hash:     "$2a$11$K5hN.ZJFzNb/LV.fB5YM8.nJKlQjnW9Zg8Yq..."
        //
        // HASH FORMAT (BCrypt):
        // $2a$11$K5hN.ZJFzNb/LV.fB5YM8.nJKlQjnW9Zg8Yq...
        //  │   │  │
        //  │   │  └─ Salt + Hash (the actual encrypted data)
        //  │   └──── Cost factor (11 = number of hashing rounds)
        //  └──────── Algorithm version (2a = BCrypt)
        //
        // WHY HASHING?
        // 1. DATABASE BREACH:
        //    - Hacker steals database
        //    - Sees: "$2a$11$K5hN..." (useless gibberish!)
        //    - Can't log in as user
        //
        // 2. EMPLOYEES CAN'T SEE PASSWORDS:
        //    - Even your own developers can't see user passwords
        //    - Better for user privacy
        //
        // 3. RAINBOW TABLE PROTECTION:
        //    - Salt makes each hash unique
        //    - Same password = different hashes for different users
        //    - Pre-computed attacks don't work
        //
        // HOW VERIFICATION WORKS:
        // Login: User enters "mypassword123"
        // Server: Hash the input → Compare with stored hash
        // Match? → Correct password!
        // No match? → Wrong password!
        // ====================================================================
        public string PasswordHash { get; set; } = string.Empty;

        // ====================================================================
        // PROPERTY 4: ROLE
        // ====================================================================
        // PURPOSE: User's role for authorization
        //
        // TYPE: string
        // COMMON VALUES: "Admin", "User", "Moderator", "Guest"
        //
        // WHAT IS A ROLE?
        // - Defines what a user can do
        // - Used with [Authorize(Roles = "Admin")]
        //
        // EXAMPLE USAGE:
        // Admin role:
        //   - Can delete users
        //   - Can access admin panel
        //   - Can modify settings
        //
        // User role:
        //   - Can view their own data
        //   - Can update their profile
        //   - Can't access admin features
        //
        // HOW IT WORKS WITH JWT:
        // 1. User logs in
        // 2. Role is embedded in JWT token as a claim
        // 3. Every request includes the token
        // 4. Server checks role from token (no database query!)
        //
        // AUTHORIZATION FLOW:
        // Request → [Authorize(Roles = "Admin")]
        //   → Extract role from JWT
        //   → If role == "Admin" → Allow
        //   → If role != "Admin" → 403 Forbidden
        //
        // COULD BE IMPROVED:
        // - Current: Single role per user
        // - Better: Multiple roles (User can be Admin + Moderator)
        // - Advanced: Permission-based instead of role-based
        // ====================================================================
        public string Role { get; set; } = string.Empty;

        // ====================================================================
        // PROPERTY 5: REFRESH TOKEN
        // ====================================================================
        // PURPOSE: Store long-lived token for getting new access tokens
        //
        // TYPE: string? (nullable - can be null)
        // EXAMPLE VALUE: "xK9pLm3nQ4r7sT8uV2wX5yZ6A1bC2dE3fG4hI5jK6="
        //
        // WHY NULLABLE?
        // - New users don't have a refresh token yet
        // - Users who log out have refresh token set to null
        // - null = "user doesn't have an active session"
        //
        // WHAT IS A REFRESH TOKEN?
        // - A random string used to get new access tokens
        // - Long-lived (7 days)
        // - Stored in database (unlike access tokens)
        //
        // TWO-TOKEN SYSTEM:
        // Access Token (JWT):
        //   - Short-lived (1 day)
        //   - Used for API requests
        //   - NOT stored in database
        //   - Contains user data
        //
        // Refresh Token:
        //   - Long-lived (7 days)
        //   - Used to get new access token
        //   - Stored in database
        //   - Random string (no user data)
        //
        // WHY STORE IN DATABASE?
        // 1. VALIDATION:
        //    - When user requests new access token
        //    - Server checks: does this refresh token match the database?
        //    - If yes → Create new access token
        //    - If no → Reject (possible attack!)
        //
        // 2. REVOCATION:
        //    - User logs out → Set RefreshToken to null
        //    - Even if user still has the old token, it won't work
        //    - Can invalidate sessions!
        //
        // 3. TOKEN ROTATION:
        //    - Each time refresh token is used → Generate new one
        //    - Old token becomes invalid
        //    - Prevents stolen tokens from being reused
        //
        // FLOW:
        // Day 1: User logs in → Gets access token (expires Day 2) + refresh token
        // Day 2: Access token expires → Use refresh token → Get new access token
        // Day 3: Still logged in (refresh token still valid)
        // Day 8: Refresh token expires → Must log in again
        // ====================================================================
        public string? RefreshToken { get; set; }

        // ====================================================================
        // PROPERTY 6: REFRESH TOKEN EXPIRY TIME
        // ====================================================================
        // PURPOSE: When the refresh token becomes invalid
        //
        // TYPE: DateTime? (nullable - can be null)
        // EXAMPLE VALUE: 2024-01-15 10:30:00
        //
        // WHY NULLABLE?
        // - New users don't have expiry time yet
        // - Users without refresh token don't need expiry time
        // - null = "no active refresh token"
        //
        // HOW IT'S SET:
        // When creating refresh token:
        //   RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7)
        //   Example: Now is Jan 1, 2024 → Expires Jan 8, 2024
        //
        // WHY UTC (Universal Time Coordinated)?
        // - Not affected by timezones
        // - Server in New York, User in Tokyo → Same time!
        // - Avoids daylight saving time bugs
        //
        // VALIDATION:
        // When user tries to refresh:
        //   if (RefreshTokenExpiryTime <= DateTime.UtcNow)
        //     → Token expired! Return 401 Unauthorized
        //   else
        //     → Token still valid! Create new access token
        //
        // EXAMPLE SCENARIO:
        // Jan 1, 10:00 AM: User logs in
        //   RefreshTokenExpiryTime = Jan 8, 10:00 AM
        //
        // Jan 5, 3:00 PM: User refreshes access token
        //   Current time: Jan 5, 3:00 PM
        //   Expiry time: Jan 8, 10:00 AM
        //   Jan 5 < Jan 8 → Still valid! ✓
        //
        // Jan 10, 5:00 PM: User tries to refresh
        //   Current time: Jan 10, 5:00 PM
        //   Expiry time: Jan 8, 10:00 AM
        //   Jan 10 > Jan 8 → Expired! ✗
        //   Return 401 → User must log in again
        // ====================================================================
        public DateTime? RefreshTokenExpiryTime { get; set; }
    }
}

// ============================================================================
// HOW THIS ENTITY IS USED THROUGHOUT THE APPLICATION
// ============================================================================
//
// 1. DATABASE TABLE CREATION (Migrations)
// ----------------------------------------
// When you run: dotnet ef migrations add Initial
// EF Core generates SQL:
//
// CREATE TABLE Users (
//     Id UNIQUEIDENTIFIER PRIMARY KEY,
//     Username NVARCHAR(MAX) NOT NULL,
//     PasswordHash NVARCHAR(MAX) NOT NULL,
//     Role NVARCHAR(MAX) NOT NULL,
//     RefreshToken NVARCHAR(MAX) NULL,
//     RefreshTokenExpiryTime DATETIME2 NULL
// )
//
// 2. REGISTRATION (AuthService.RegisterAsync)
// --------------------------------------------
// var user = new User {
//     Username = "john@example.com",
//     PasswordHash = "$2a$11$...",
//     Role = ""
// };
// context.Users.Add(user);
// await context.SaveChangesAsync();
//
// SQL: INSERT INTO Users (Id, Username, PasswordHash, Role)
//      VALUES (NEWID(), 'john@example.com', '$2a$11$...', '')
//
// 3. LOGIN (AuthService.LoginAsync)
// ----------------------------------
// var user = await context.Users
//     .FirstOrDefaultAsync(u => u.Username == "john@example.com");
//
// SQL: SELECT * FROM Users WHERE Username = 'john@example.com'
//
// 4. TOKEN CREATION (AuthService.CreateToken)
// --------------------------------------------
// var claims = new List<Claim> {
//     new Claim(ClaimTypes.Name, user.Username),
//     new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
//     new Claim(ClaimTypes.Role, user.Role)
// };
//
// User data from database → Embedded in JWT token
//
// 5. REFRESH TOKEN STORAGE (AuthService.GenerateAndSaveRefreshTokenAsync)
// -------------------------------------------------------------------------
// user.RefreshToken = "xK9pL...";
// user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);
// await context.SaveChangesAsync();
//
// SQL: UPDATE Users
//      SET RefreshToken = 'xK9pL...', RefreshTokenExpiryTime = '2024-01-08'
//      WHERE Id = '123e4567...'
//
// ============================================================================

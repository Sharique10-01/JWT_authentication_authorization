// ============================================================================
// USER DTO - DATA TRANSFER OBJECT FOR LOGIN/REGISTER
// ============================================================================
// DTO = Data Transfer Object
//
// WHAT IS A DTO?
// - A simple object that carries data between layers
// - Used to transfer data over the network (HTTP)
// - Think of it as a "shipping container" for data
//
// WHY USE DTOs INSTEAD OF ENTITIES?
// 1. SECURITY:
//    - Entity (User) has sensitive fields: PasswordHash, RefreshToken, Id
//    - DTO only has what we need: Username and Password
//    - Never expose database entities directly to the outside world!
//
// 2. DECOUPLING:
//    - API requests/responses separate from database structure
//    - Can change database without breaking API
//    - Can change API without changing database
//
// 3. VALIDATION:
//    - DTOs can have different validation rules than entities
//    - Example: Entity requires PasswordHash, DTO requires Password
//
// 4. CLARITY:
//    - Clear what data is expected for each operation
//    - UserDto for login/register (needs plain password)
//    - User entity for database (has hashed password)
//
// FLOW:
// Browser sends: { "username": "john", "password": "secret123" }
//   → Deserialized to UserDto
//   → Controller receives UserDto
//   → Service converts to User entity
//   → User entity saved to database
// ============================================================================

namespace JwtAuthDotNet9.Models
{
    public class UserDto
    {
        // ====================================================================
        // PROPERTY 1: USERNAME
        // ====================================================================
        // PURPOSE: User's login identifier
        //
        // USED IN:
        // - Registration: New user's desired username
        // - Login: Existing user's username
        //
        // TYPICAL VALUES:
        // - Email: "john@example.com"
        // - Username: "john123"
        //
        // WHY IN DTO?
        // - Needed for both login and registration
        // - Safe to send over network (not sensitive)
        //
        // VALIDATION (Could add):
        // [Required] - Must not be empty
        // [EmailAddress] - Must be valid email format
        // [MinLength(3)] - At least 3 characters
        // ====================================================================
        public string Username { get; set; } = string.Empty;

        // ====================================================================
        // PROPERTY 2: PASSWORD (PLAIN TEXT!)
        // ====================================================================
        // PURPOSE: User's password in PLAIN TEXT
        //
        // ⚠️ CRITICAL SECURITY NOTES:
        // 1. This is PLAIN TEXT password from user
        // 2. NEVER store this in database!
        // 3. NEVER log this to console/files!
        // 4. Hash it immediately in AuthService
        // 5. Only exists in memory during request
        //
        // FLOW:
        // Browser: User types "mypassword123"
        //   → Sent over HTTPS (encrypted in transit)
        //   → Arrives at server as UserDto.Password = "mypassword123"
        //   → AuthService hashes it: "$2a$11$..."
        //   → Plain password discarded from memory
        //   → Only hash is stored in database
        //
        // WHY PLAIN TEXT IN DTO?
        // - User enters plain password (they don't know what hashing is!)
        // - Need plain password to hash it with salt
        // - Can't hash on client side (salt is server-side)
        //
        // SECURITY MEASURES:
        // 1. HTTPS required (encrypted during transmission)
        // 2. Immediate hashing (not stored anywhere)
        // 3. No logging (don't write to logs)
        // 4. Memory cleared after use (GC collects it)
        //
        // VALIDATION (Could add):
        // [Required] - Must not be empty
        // [MinLength(8)] - At least 8 characters
        // [RegularExpression] - Must have uppercase, number, symbol
        // ====================================================================
        public string Password { get; set; } = string.Empty;
    }
}

// ============================================================================
// HOW THIS DTO IS USED
// ============================================================================
//
// REGISTRATION FLOW:
// ------------------
// 1. User fills form:
//    Username: "john@example.com"
//    Password: "mypassword123"
//
// 2. JavaScript sends POST request:
//    POST /api/auth/register
//    Body: { "username": "john@example.com", "password": "mypassword123" }
//
// 3. .NET deserializes JSON → UserDto:
//    var dto = new UserDto {
//        Username = "john@example.com",
//        Password = "mypassword123"
//    };
//
// 4. Controller passes to Service:
//    var user = await authService.RegisterAsync(dto);
//
// 5. Service hashes password and creates User entity:
//    var user = new User {
//        Username = dto.Username,  // "john@example.com"
//        PasswordHash = HashPassword(dto.Password)  // "$2a$11$..."
//    };
//
// 6. User entity saved to database
//    DTO is discarded (garbage collected)
//
// LOGIN FLOW:
// -----------
// 1. User fills login form:
//    Username: "john@example.com"
//    Password: "mypassword123"
//
// 2. JavaScript sends POST request:
//    POST /api/auth/login
//    Body: { "username": "john@example.com", "password": "mypassword123" }
//
// 3. .NET deserializes JSON → UserDto
//
// 4. Service retrieves User from database:
//    var user = await context.Users.FirstOrDefaultAsync(u => u.Username == dto.Username);
//
// 5. Service verifies password:
//    VerifyHashedPassword(user.PasswordHash, dto.Password)
//    Compares: Hash("mypassword123") == user.PasswordHash
//
// 6. If match → Create tokens
//    If no match → Return null
//
// ============================================================================
//
// DTO vs ENTITY COMPARISON:
// --------------------------
//
// UserDto (Data Transfer Object):
// --------------------------------
// Purpose: Transfer data over network
// Has: Username, Password (plain text)
// Used: In HTTP requests/responses
// Lifetime: Duration of HTTP request
// Security: Password is plain text (sent over HTTPS)
//
// User Entity:
// ------------
// Purpose: Represent database table
// Has: Id, Username, PasswordHash, Role, RefreshToken, RefreshTokenExpiryTime
// Used: In database operations
// Lifetime: Persisted in database
// Security: Password is hashed (never plain text)
//
// WHY SEPARATE?
// - DTO: What the outside world sees
// - Entity: What the database stores
// - Never the same! Security and separation of concerns.
//
// ============================================================================

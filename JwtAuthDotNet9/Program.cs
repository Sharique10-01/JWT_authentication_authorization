// ============================================================================
// PROGRAM.CS - THE ENTRY POINT & CONFIGURATION CENTER
// ============================================================================
// This is the FIRST file that runs when your application starts.
// Think of it as the "control center" where we set up EVERYTHING before
// the application starts handling requests.
//
// FLOW: This file runs ONCE at startup → Configures services → Starts the app
// ============================================================================

using JwtAuthDotNet9.Data;
using JwtAuthDotNet9.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Scalar.AspNetCore;
using System.Text;

// ============================================================================
// STEP 1: CREATE THE APPLICATION BUILDER
// ============================================================================
// WebApplicationBuilder is like a "factory" that helps us build our web app.
// It reads configuration from appsettings.json, environment variables, etc.
// ============================================================================
var builder = WebApplication.CreateBuilder(args);

// ============================================================================
// STEP 2: REGISTER SERVICES (Dependency Injection Container)
// ============================================================================
// Services are reusable components that our app needs. We register them here
// so they can be "injected" into controllers and other classes automatically.
// Think of this as telling .NET: "Hey, when someone needs X, give them Y"
// ============================================================================

// ----------------------------------------------------------------------------
// Add Controllers Service
// ----------------------------------------------------------------------------
// WHY: Controllers handle HTTP requests (GET, POST, etc.)
// WHAT IT DOES: Scans all classes with [ApiController] attribute and registers them
// WHEN CALLED: Whenever a HTTP request comes in, .NET routes it to the right controller
// ----------------------------------------------------------------------------
builder.Services.AddControllers();

// ----------------------------------------------------------------------------
// Add OpenAPI/Swagger Service
// ----------------------------------------------------------------------------
// WHY: Generates API documentation automatically (for testing/debugging)
// WHAT IT DOES: Creates interactive docs where you can test your API endpoints
// ACCESS AT: https://localhost:5001/scalar/v1 (when app is running)
// ----------------------------------------------------------------------------
builder.Services.AddOpenApi();

// ============================================================================
// STEP 3: CONFIGURE DATABASE
// ============================================================================
// WHY: We need a place to store user data (username, password hash, etc.)
// WHAT: Entity Framework Core (EF Core) = .NET's way to talk to databases
// HOW: We tell EF Core to use SQL Server and give it the connection string
// ============================================================================
builder.Services.AddDbContext<UserDbContext>(options =>
    // Get connection string from appsettings.json → ConnectionStrings:UserDatabase
    // UseSqlServer = "Use Microsoft SQL Server as the database"
    // UserDbContext will be injected into services that need database access
    options.UseSqlServer(builder.Configuration.GetConnectionString("UserDatabase")));

// ============================================================================
// STEP 4: CONFIGURE JWT AUTHENTICATION (THE HEART OF THIS APP!)
// ============================================================================
// This is WHERE THE MAGIC HAPPENS!
// We're telling .NET: "Use JWT tokens for authentication"
//
// FLOW:
// 1. User sends request with JWT token in header
// 2. .NET intercepts it (before reaching controller)
// 3. Validates the token using these settings
// 4. If valid → Request proceeds to controller with user info
// 5. If invalid → Returns 401 Unauthorized (request stops here)
// ============================================================================
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    // JwtBearerDefaults.AuthenticationScheme = "Bearer"
    // This means tokens must be sent as: Authorization: Bearer <token>

    .AddJwtBearer(options =>
    {
        // -----------------------------------------------------------------------
        // Token Validation Parameters - The Rules for Validating Tokens
        // -----------------------------------------------------------------------
        // Think of this as a checklist: "For a token to be valid, it must..."
        // -----------------------------------------------------------------------
        options.TokenValidationParameters = new TokenValidationParameters
        {
            // ===================================================================
            // 1. ISSUER VALIDATION
            // ===================================================================
            // QUESTION: "Who created this token?"
            // WHY: Prevent tokens from other apps being used here
            // EXAMPLE: If token says issuer="HackerApp", we reject it!
            // ===================================================================
            ValidateIssuer = true, // Enable issuer checking
            ValidIssuer = builder.Configuration["AppSettings:Issuer"], // Expected value: "MyAwesomeApp"

            // ===================================================================
            // 2. AUDIENCE VALIDATION
            // ===================================================================
            // QUESTION: "Who is this token for?"
            // WHY: Token meant for "AppA" shouldn't work on "AppB"
            // EXAMPLE: Token with audience="SomeOtherApp" gets rejected
            // ===================================================================
            ValidateAudience = true, // Enable audience checking
            ValidAudience = builder.Configuration["AppSettings:Audience"], // Expected value: "MyAwesomeAudience"

            // ===================================================================
            // 3. LIFETIME VALIDATION
            // ===================================================================
            // QUESTION: "Is this token expired?"
            // WHY: Old tokens should stop working for security
            // HOW: Checks the "exp" (expiration) claim in the token
            // EXAMPLE: Token created at 2:00 PM, expires 3:00 PM → At 3:01 PM, rejected!
            // ===================================================================
            ValidateLifetime = true, // Enable expiration checking

            // ===================================================================
            // 4. SIGNATURE VALIDATION (MOST IMPORTANT!)
            // ===================================================================
            // QUESTION: "Has this token been tampered with?"
            // WHY: This prevents hackers from changing token data
            // HOW: Uses the secret key to verify the signature
            //
            // THE SECRET KEY:
            // - Stored in appsettings.json → AppSettings:Token
            // - ONLY the server knows this key
            // - Used to create signature when token is created
            // - Used to verify signature when token is validated
            //
            // METAPHOR: Like a wax seal on a letter
            // - King has a secret ring (secret key)
            // - Presses ring into wax (creates signature)
            // - Anyone can verify it's the king's seal
            // - But nobody can CREATE a fake seal without the ring!
            // ===================================================================
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(builder.Configuration["AppSettings:Token"]!)),
                // Why Encoding.UTF8.GetBytes?
                // - Secret key in appsettings.json is a string
                // - Cryptographic functions need bytes
                // - So we convert: "MySecretKey" → [77, 121, 83, 101...]

            ValidateIssuerSigningKey = true // Enable signature checking
            // If false, ANY token would be accepted (VERY DANGEROUS!)
        };
    });

// ============================================================================
// STEP 5: REGISTER CUSTOM SERVICES (Dependency Injection)
// ============================================================================
// WHY: AuthService contains our business logic (login, register, etc.)
// WHAT: We're saying "When someone asks for IAuthService, give them AuthService"
// LIFETIME: "Scoped" means one instance per HTTP request
//   - Request 1 → New AuthService instance
//   - Request 2 → New AuthService instance
//   - This is safer than "Singleton" (one instance for ALL requests)
// ============================================================================
builder.Services.AddScoped<IAuthService, AuthService>();
// Interface: IAuthService (contract - what methods exist)
// Implementation: AuthService (actual code that does the work)
// Controllers will ask for IAuthService, .NET will provide AuthService

// ============================================================================
// STEP 6: BUILD THE APPLICATION
// ============================================================================
// All configuration is done! Now we BUILD the app.
// This creates the actual web application with all services configured.
// ============================================================================
var app = builder.Build();

// ============================================================================
// STEP 7: CONFIGURE THE HTTP PIPELINE (Middleware)
// ============================================================================
// Middleware = Code that runs on EVERY request
// Think of it as a series of gates a request passes through:
//
// Request → [Gate 1] → [Gate 2] → [Gate 3] → Controller → Response
//
// ORDER MATTERS! Requests pass through in the order we add them.
// ============================================================================

// ----------------------------------------------------------------------------
// Development-Only Middleware
// ----------------------------------------------------------------------------
// Only runs when we're developing (not in production)
// WHY: We want API docs during development, but not in production
// ----------------------------------------------------------------------------
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();           // Generates OpenAPI specification
    app.MapScalarApiReference(); // Creates interactive API documentation UI
}

// ----------------------------------------------------------------------------
// HTTPS Redirection Middleware
// ----------------------------------------------------------------------------
// WHY: Forces all HTTP requests to use HTTPS (encrypted)
// EXAMPLE: User visits http://example.com → Redirected to https://example.com
// SECURITY: Prevents man-in-the-middle attacks
// ----------------------------------------------------------------------------
app.UseHttpsRedirection();

// ============================================================================
// AUTHORIZATION MIDDLEWARE (CRITICAL FOR JWT!)
// ============================================================================
// IMPORTANT: There's a missing line here! Should be:
//   app.UseAuthentication(); // Who are you? (checks JWT)
//   app.UseAuthorization();  // What can you do? (checks roles/permissions)
//
// CURRENT CODE ISSUE: Only has UseAuthorization, missing UseAuthentication!
// This might still work because AddAuthentication adds the middleware internally,
// but best practice is to explicitly add both.
//
// THE FLOW SHOULD BE:
// Request → UseAuthentication (validate JWT, extract claims)
//        → UseAuthorization (check if user has permission)
//        → Controller
// ============================================================================
app.UseAuthorization();
// TODO: Add app.UseAuthentication() before this line!

// ----------------------------------------------------------------------------
// Map Controllers
// ----------------------------------------------------------------------------
// WHY: Tells the app "Look for controllers and route requests to them"
// HOW: Scans for classes with [ApiController] attribute
// EXAMPLE: GET /api/auth/login → Routes to AuthController.Login()
// ----------------------------------------------------------------------------
app.MapControllers();

// ============================================================================
// STEP 8: RUN THE APPLICATION
// ============================================================================
// This starts the web server and begins listening for HTTP requests.
// The application will keep running until:
// - You press Ctrl+C
// - An unhandled error occurs
// - The process is killed
// ============================================================================
app.Run();

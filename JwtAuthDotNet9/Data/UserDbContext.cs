// ============================================================================
// USER DB CONTEXT - THE DATABASE CONNECTION & CONFIGURATION
// ============================================================================
// This is the "bridge" between your C# code and the database.
// Think of it as a "database manager" that handles all database operations.
//
// WHAT IS A DbContext?
// - DbContext = Database Context (from Entity Framework Core)
// - Represents a session with the database
// - Allows you to query and save data
// - Tracks changes to entities
// - Generates SQL queries automatically
//
// ANALOGY:
// If Database is a library,
// DbContext is the librarian who:
// - Fetches books (reads data)
// - Returns books (saves data)
// - Keeps track of what you borrowed (change tracking)
// - Knows where everything is (table mapping)
//
// HOW IT WORKS:
// C# Code: context.Users.Add(user);
// DbContext: Generates SQL: INSERT INTO Users...
// Database: Executes query and stores data
// ============================================================================

using JwtAuthDotNet9.Entities;
using Microsoft.EntityFrameworkCore;

namespace JwtAuthDotNet9.Data
{
    // ========================================================================
    // PRIMARY CONSTRUCTOR (C# 12 Feature)
    // ========================================================================
    // public class UserDbContext(DbContextOptions<UserDbContext> options)
    //
    // This receives configuration from Program.cs:
    // - Database provider (SQL Server, PostgreSQL, etc.)
    // - Connection string (where is the database?)
    // - Other settings
    //
    // CONFIGURED IN PROGRAM.CS:
    // builder.Services.AddDbContext<UserDbContext>(options =>
    //     options.UseSqlServer(connectionString));
    //
    // HOW IT GETS HERE:
    // 1. Program.cs registers UserDbContext with SQL Server
    // 2. Dependency Injection creates DbContextOptions
    // 3. DI passes options to this constructor
    // 4. UserDbContext is ready to use!
    // ========================================================================
    public class UserDbContext(DbContextOptions<UserDbContext> options) : DbContext(options)
    // : DbContext(options) → Pass options to base class
    {
        // ====================================================================
        // DbSet<User> - THE USERS TABLE
        // ====================================================================
        // WHAT IS DbSet?
        // - Represents a table in the database
        // - Each DbSet<T> = One table
        // - T = The entity type (User in this case)
        //
        // NAMING CONVENTION:
        // - Property name "Users" → Table name "Users"
        // - If you want different name, use [Table("CustomName")]
        //
        // WHAT YOU CAN DO WITH DbSet:
        // ----------------------------------------------------------------
        //
        // 1. QUERY (SELECT):
        //    var user = await context.Users.FirstOrDefaultAsync(u => u.Username == "john");
        //    SQL: SELECT * FROM Users WHERE Username = 'john' LIMIT 1
        //
        // 2. ADD (INSERT):
        //    context.Users.Add(newUser);
        //    await context.SaveChangesAsync();
        //    SQL: INSERT INTO Users (Id, Username, PasswordHash, ...) VALUES (...)
        //
        // 3. UPDATE:
        //    user.Username = "newname";
        //    await context.SaveChangesAsync();
        //    SQL: UPDATE Users SET Username = 'newname' WHERE Id = '...'
        //
        // 4. DELETE (REMOVE):
        //    context.Users.Remove(user);
        //    await context.SaveChangesAsync();
        //    SQL: DELETE FROM Users WHERE Id = '...'
        //
        // 5. FIND BY ID:
        //    var user = await context.Users.FindAsync(userId);
        //    SQL: SELECT * FROM Users WHERE Id = '...'
        //
        // 6. COUNT:
        //    var count = await context.Users.CountAsync();
        //    SQL: SELECT COUNT(*) FROM Users
        //
        // 7. LINQ QUERIES:
        //    var admins = await context.Users
        //        .Where(u => u.Role == "Admin")
        //        .OrderBy(u => u.Username)
        //        .ToListAsync();
        //    SQL: SELECT * FROM Users WHERE Role = 'Admin' ORDER BY Username
        //
        // WHY "public DbSet<User> Users { get; set; }"?
        // - public: Can be accessed from services/controllers
        // - DbSet<User>: Collection of User entities
        // - Users: The property name (becomes table name)
        // - { get; set; }: Auto-property (EF Core sets this up)
        //
        // CHANGE TRACKING:
        // ----------------------------------------------------------------
        // EF Core automatically tracks changes!
        //
        // Example:
        // var user = await context.Users.FindAsync(userId);  // User is now "tracked"
        // user.Username = "newname";                          // Change detected!
        // await context.SaveChangesAsync();                   // UPDATE query generated
        //
        // EF Core knows:
        // - Which entities are new → INSERT
        // - Which entities changed → UPDATE
        // - Which entities were removed → DELETE
        // - Which entities are unchanged → Skip
        //
        // IMPORTANT: SaveChangesAsync() must be called!
        // Changes are only persisted to database after SaveChangesAsync()
        // ====================================================================
        public DbSet<User> Users { get; set; }
    }
}

// ============================================================================
// HOW DbContext IS USED THROUGHOUT THE APPLICATION
// ============================================================================
//
// REGISTRATION IN PROGRAM.CS:
// ----------------------------
// builder.Services.AddDbContext<UserDbContext>(options =>
//     options.UseSqlServer(builder.Configuration.GetConnectionString("UserDatabase")));
//
// This tells .NET:
// - "UserDbContext exists"
// - "Use SQL Server as the database"
// - "Connection string is in appsettings.json"
//
// CONNECTION STRING (appsettings.json):
// --------------------------------------
// "ConnectionStrings": {
//   "UserDatabase": "Server=(localdb)\\MSSQLLocalDB;Database=UserDb;..."
// }
//
// Breakdown:
// - Server=(localdb)\\MSSQLLocalDB → Local SQL Server instance
// - Database=UserDb → Database name
// - Trusted_Connection=true → Use Windows authentication
//
// ============================================================================
//
// DEPENDENCY INJECTION (AuthService):
// ------------------------------------
// public class AuthService(UserDbContext context, ...) : IAuthService
//
// .NET automatically:
// 1. Creates UserDbContext instance
// 2. Configures it with SQL Server
// 3. Injects it into AuthService
// 4. AuthService uses it to access database
//
// ============================================================================
//
// USAGE IN AuthService.RegisterAsync:
// ------------------------------------
// public async Task<User?> RegisterAsync(UserDto request)
// {
//     // Query database
//     if (await context.Users.AnyAsync(u => u.Username == request.Username))
//         return null;
//
//     // Create entity
//     var user = new User { Username = request.Username, ... };
//
//     // Add to DbSet (not saved yet!)
//     context.Users.Add(user);
//
//     // Save to database (executes INSERT)
//     await context.SaveChangesAsync();
//
//     return user;
// }
//
// ============================================================================
//
// USAGE IN AuthService.LoginAsync:
// ---------------------------------
// public async Task<TokenResponseDto?> LoginAsync(UserDto request)
// {
//     // Query database
//     var user = await context.Users
//         .FirstOrDefaultAsync(u => u.Username == request.Username);
//
//     if (user is null)
//         return null;
//
//     // ... verify password, create tokens ...
//
//     // Update entity
//     user.RefreshToken = newToken;
//     user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);
//
//     // Save to database (executes UPDATE)
//     await context.SaveChangesAsync();
//
//     return tokenResponse;
// }
//
// ============================================================================
//
// ENTITY FRAMEWORK CORE MAGIC:
// =============================
//
// YOU WRITE:
// ----------
// var user = await context.Users.FirstOrDefaultAsync(u => u.Username == "john");
//
// EF CORE GENERATES:
// ------------------
// SELECT TOP 1 [Id], [Username], [PasswordHash], [Role], [RefreshToken], [RefreshTokenExpiryTime]
// FROM [Users]
// WHERE [Username] = 'john'
//
// ============================================================================
//
// YOU WRITE:
// ----------
// context.Users.Add(new User { Username = "john", PasswordHash = "..." });
// await context.SaveChangesAsync();
//
// EF CORE GENERATES:
// ------------------
// INSERT INTO [Users] ([Id], [Username], [PasswordHash], [Role])
// VALUES (NEWID(), 'john', '...', '')
//
// ============================================================================
//
// YOU WRITE:
// ----------
// user.RefreshToken = "newtoken";
// await context.SaveChangesAsync();
//
// EF CORE GENERATES:
// ------------------
// UPDATE [Users]
// SET [RefreshToken] = 'newtoken'
// WHERE [Id] = '123e4567-...'
//
// ============================================================================
//
// DATABASE MIGRATIONS:
// ====================
//
// WHAT ARE MIGRATIONS?
// - Version control for your database schema
// - Each migration = A set of database changes
// - Can upgrade (apply) or downgrade (revert) database
//
// CREATING A MIGRATION:
// ---------------------
// Command: dotnet ef migrations add Initial
//
// What happens:
// 1. EF Core scans your DbContext and entities
// 2. Compares to current database state
// 3. Generates migration file with SQL changes
// 4. Creates snapshot of current schema
//
// APPLYING A MIGRATION:
// ---------------------
// Command: dotnet ef database update
//
// What happens:
// 1. EF Core connects to database
// 2. Checks which migrations are applied
// 3. Executes pending migrations in order
// 4. Updates __EFMigrationsHistory table
//
// EXAMPLE MIGRATION:
// ------------------
// migrationBuilder.CreateTable(
//     name: "Users",
//     columns: table => new
//     {
//         Id = table.Column<Guid>(nullable: false),
//         Username = table.Column<string>(nullable: false),
//         PasswordHash = table.Column<string>(nullable: false),
//         Role = table.Column<string>(nullable: false),
//         RefreshToken = table.Column<string>(nullable: true),
//         RefreshTokenExpiryTime = table.Column<DateTime>(nullable: true)
//     },
//     constraints: table =>
//     {
//         table.PrimaryKey("PK_Users", x => x.Id);
//     });
//
// ============================================================================
//
// BEST PRACTICES:
// ===============
//
// 1. ALWAYS USE ASYNC METHODS:
//    ✅ await context.SaveChangesAsync()
//    ❌ context.SaveChanges()  // Blocks the thread!
//
// 2. CALL SaveChangesAsync AFTER MODIFICATIONS:
//    context.Users.Add(user);
//    await context.SaveChangesAsync();  // Don't forget this!
//
// 3. USE SCOPED LIFETIME:
//    builder.Services.AddDbContext<UserDbContext>()  // Scoped by default
//    - New instance per HTTP request
//    - Automatically disposed after request
//    - Thread-safe for that request
//
// 4. DON'T TRACK IF NOT NEEDED:
//    var users = await context.Users.AsNoTracking().ToListAsync();
//    - Faster for read-only queries
//    - Less memory usage
//    - No change tracking overhead
//
// 5. DISPOSE IS AUTOMATIC:
//    - Dependency Injection handles disposal
//    - No need to manually dispose
//    - But you CAN use: using var context = new UserDbContext(...);
//
// ============================================================================

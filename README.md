# JWT Authentication & Authorization in .NET 9

A complete, production-ready implementation of JWT (JSON Web Token) authentication and authorization in .NET 9, featuring access tokens, refresh tokens, role-based authorization, and comprehensive documentation.

## 🌟 Features

- ✅ **JWT Authentication** - Secure token-based authentication
- ✅ **Refresh Tokens** - Long-lived tokens with rotation for better security
- ✅ **Role-Based Authorization** - Admin and User role management
- ✅ **Password Hashing** - BCrypt password hashing for security
- ✅ **Entity Framework Core** - SQL Server database with migrations
- ✅ **Comprehensive Documentation** - Every line of code is explained
- ✅ **Best Practices** - Production-ready security patterns

## 📚 Learning Resources

This project includes:
- **JWT_COMPLETE_GUIDE.md** - A comprehensive guide explaining JWT from zero to hero
- **Inline Comments** - Every file has detailed comments explaining what, why, and how

## 🛠️ Tech Stack

- **.NET 9** - Latest .NET framework
- **C# 12** - With primary constructors and other modern features
- **Entity Framework Core** - ORM for database operations
- **SQL Server** - Database (LocalDB for development)
- **JWT Bearer Authentication** - Token-based auth
- **BCrypt** - Password hashing

## 🚀 Getting Started

### Prerequisites

- [.NET 9 SDK](https://dotnet.microsoft.com/download/dotnet/9.0)
- [SQL Server LocalDB](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/sql-server-express-localdb) (comes with Visual Studio)
- [Visual Studio 2022](https://visualstudio.microsoft.com/) or [VS Code](https://code.visualstudio.com/)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/Sharique10-01/JWT_authentication_authorization.git
   cd JWT_authentication_authorization
   ```

2. **Restore packages**
   ```bash
   dotnet restore
   ```

3. **Update database connection string** (if needed)

   Edit `appsettings.json`:
   ```json
   "ConnectionStrings": {
     "UserDatabase": "Server=(localdb)\\MSSQLLocalDB;Database=UserDb;Trusted_Connection=true;TrustServerCertificate=true;"
   }
   ```

4. **Apply database migrations**
   ```bash
   dotnet ef database update
   ```

5. **Run the application**
   ```bash
   dotnet run
   ```

6. **Access the API documentation**

   Navigate to: `https://localhost:5001/scalar/v1`

## 📖 API Endpoints

### Authentication Endpoints

#### 1. Register
```http
POST /api/auth/register
Content-Type: application/json

{
  "username": "john@example.com",
  "password": "mypassword123"
}
```

**Response:**
```json
{
  "id": "123e4567-e89b-12d3-a456-426614174000",
  "username": "john@example.com",
  "role": ""
}
```

#### 2. Login
```http
POST /api/auth/login
Content-Type: application/json

{
  "username": "john@example.com",
  "password": "mypassword123"
}
```

**Response:**
```json
{
  "accessToken": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "xK9pLm3nQ4r7sT8uV2wX5yZ6A1bC2dE3fG4hI5jK6="
}
```

#### 3. Refresh Token
```http
POST /api/auth/refresh-token
Content-Type: application/json

{
  "userId": "123e4567-e89b-12d3-a456-426614174000",
  "refreshToken": "xK9pLm3nQ4r7sT8uV2wX5yZ6A1bC2dE3fG4hI5jK6="
}
```

**Response:**
```json
{
  "accessToken": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "yL0qMn4oR5s8T9vW3xY6z7B8cD9eF0gH1iJ2kL3="
}
```

### Protected Endpoints

#### 4. Authenticated Endpoint (Requires valid JWT)
```http
GET /api/auth
Authorization: Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9...
```

**Response:**
```
"You are authenticated!"
```

#### 5. Admin-Only Endpoint (Requires Admin role)
```http
GET /api/auth/admin-only
Authorization: Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9...
```

**Response:**
```
"You are an admin!"
```

## 🔐 Security Features

### 1. Password Hashing
- Passwords are hashed using **BCrypt** with salt
- Never stored in plain text
- One-way encryption (impossible to reverse)

### 2. JWT Tokens
- **Access Token**: Short-lived (1 day), used for API requests
- **Refresh Token**: Long-lived (7 days), used to get new access tokens
- Signed with HMAC-SHA512 algorithm
- Validated on every request

### 3. Token Rotation
- New refresh token generated on every refresh
- Old tokens become invalid
- Prevents replay attacks

### 4. Role-Based Authorization
- `[Authorize]` - Requires authentication
- `[Authorize(Roles = "Admin")]` - Requires specific role

## 🏗️ Project Structure

```
JwtAuthDotNet9/
├── Controllers/
│   └── AuthController.cs          # API endpoints
├── Services/
│   ├── IAuthService.cs            # Service interface
│   └── AuthService.cs             # Business logic
├── Entities/
│   └── User.cs                    # Database entity
├── Models/
│   ├── UserDto.cs                 # Login/Register DTO
│   ├── TokenResponseDto.cs        # Token response DTO
│   └── RefreshTokenRequestDto.cs  # Refresh request DTO
├── Data/
│   └── UserDbContext.cs           # Database context
├── Migrations/                    # EF Core migrations
├── Program.cs                     # App configuration
└── appsettings.json              # Configuration
```

## 🔄 Authentication Flow

### Registration Flow
```
User → Fill Form → POST /api/auth/register
  → Server validates username
  → Hash password with BCrypt
  → Save user to database
  → Return user object
```

### Login Flow
```
User → Enter credentials → POST /api/auth/login
  → Server finds user in database
  → Verify password hash
  → Generate JWT access token (1 day expiry)
  → Generate refresh token (7 days expiry)
  → Save refresh token to database
  → Return both tokens
  → Client stores tokens
```

### Authenticated Request Flow
```
User → Make request with JWT → GET /api/auth
  → Authentication Middleware intercepts
  → Validate token signature
  → Check expiration
  → Extract user claims
  → If valid → Request proceeds
  → If invalid → 401 Unauthorized
```

### Token Refresh Flow
```
Access token expires → Client detects 401
  → POST /api/auth/refresh-token with refresh token
  → Server validates refresh token
  → Generate NEW access token
  → Generate NEW refresh token
  → Update database
  → Return new tokens
  → Client stores new tokens
  → Retry original request
```

## 🧪 Testing with curl

### Register a new user
```bash
curl -X POST https://localhost:5001/api/auth/register \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"test@example.com\",\"password\":\"Test123!\"}"
```

### Login
```bash
curl -X POST https://localhost:5001/api/auth/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"test@example.com\",\"password\":\"Test123!\"}"
```

### Access protected endpoint
```bash
curl -X GET https://localhost:5001/api/auth \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN_HERE"
```

## 📝 Configuration

### appsettings.json

```json
{
  "ConnectionStrings": {
    "UserDatabase": "Server=(localdb)\\MSSQLLocalDB;Database=UserDb;Trusted_Connection=true;TrustServerCertificate=true;"
  },
  "AppSettings": {
    "Token": "YourSuperSecretKeyThatShouldBeVeryLong!!!",
    "Issuer": "YourAppName",
    "Audience": "YourAppUsers"
  }
}
```

**Important:**
- Change the `Token` secret key in production!
- Use environment variables or Azure Key Vault for secrets
- Never commit secrets to Git

## 🎓 Learning Path

1. **Start with the guide**: Read `JWT_COMPLETE_GUIDE.md`
2. **Explore the code**: Each file has comprehensive comments
3. **Run the application**: Test the endpoints
4. **Read the flows**: Understand how everything connects
5. **Modify and experiment**: Try adding new features

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 👨‍💻 Author

**Sharique Khan**
- GitHub: [@Sharique10-01](https://github.com/Sharique10-01)

## 🙏 Acknowledgments

- Microsoft for .NET and Entity Framework Core
- The JWT community for authentication standards
- All contributors and learners

## 📚 Additional Resources

- [JWT.io](https://jwt.io/) - JWT debugger and documentation
- [.NET Documentation](https://docs.microsoft.com/dotnet/)
- [Entity Framework Core](https://docs.microsoft.com/ef/core/)
- [ASP.NET Core Security](https://docs.microsoft.com/aspnet/core/security/)

## 🔮 Future Enhancements

- [ ] Email verification
- [ ] Password reset functionality
- [ ] Two-factor authentication (2FA)
- [ ] Account lockout after failed attempts
- [ ] Audit logging
- [ ] Rate limiting
- [ ] OAuth integration (Google, Facebook)
- [ ] Permission-based authorization

---

**Happy Coding! 🚀**

If you find this project helpful, please give it a ⭐ on GitHub!

# SecureVault

A Blazor WebAssembly application with an ASP.NET Core API backend featuring JWT authentication, role-based authorization, and ASP.NET Identity with a SQLite database.

## Security Notes

- Password hashing is managed by ASP.NET Identity's `UserManager`.
- Plain-text passwords sent to the login endpoint are automatically secured by TLS via HTTPS redirection.

## Prerequisites

- [.NET 10 SDK](https://dotnet.microsoft.com/download) (or later)
- A terminal (PowerShell, bash, etc.)

## Project Structure

| Project | Description |
|---|---|
| `SecureVault.Api` | ASP.NET Core Web API — authentication endpoints, Identity, SQLite database |
| `SecureVault.Client` | Blazor WebAssembly front-end |
| `SecureVault.Shared` | Shared models and contracts used by both API and Client |
| `SecureVault.Tests` | xUnit test project |

## Getting Started

### 1. Clone the Repository

```bash
git clone <repository-url>
cd CapstoneProject
```

### 2. Restore Dependencies

```bash
dotnet restore
```

### 3. Run the API

The API uses a SQLite database (`localdb.sqlite`) that is created automatically on first run. Roles and a default **SuperAdmin** user are seeded at startup.

```bash
cd SecureVault.Api
dotnet run --launch-profile https
```

The API will be available at **https://localhost:7091**.

### 4. Run the Client

Open a **second terminal** from the project root:

```bash
cd SecureVault.Client
dotnet run --launch-profile https
```

The client will open in your browser at **https://localhost:7107**.

### 5. Log In

A default SuperAdmin account is seeded automatically:

| Field | Value |
|---|---|
| Username | `superadmin` |
| Password | `superAdmin123_!!` |

You can also register a new user from the `/register` page.

## Running Tests

From the project root:

```bash
dotnet test
```

This will build the solution and execute all xUnit tests in the `SecureVault.Tests` project.

## Configuration

Key settings are in `SecureVault.Api/appsettings.json`:

- **JwtSettings** — issuer, audience, signing key, and token expiration (default: 3 minutes).
- **DefaultSuperAdminPassword** — password used to seed the SuperAdmin account.

## Manual API Testing

The file [`SecureVault.Api/SecureVault.Api.http`](SecureVault.Api/SecureVault.Api.http) contains pre-built HTTP requests for manually testing every API endpoint directly from your IDE (Rider, Visual Studio, or VS Code with the REST Client extension). Open the file for detailed usage instructions, including how to set the access and refresh token variables.

## Troubleshooting

- **HTTPS certificate errors**: Run `dotnet dev-certs https --trust` to trust the local development certificate.
- **Port conflicts**: Update the URLs in `Properties/launchSettings.json` for each project and the CORS origins in `SecureVault.Api/Program.cs`.
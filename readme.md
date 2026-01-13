# OAuth 2.0 Flow Tester

A comprehensive Flask application to test and debug OAuth 2.0 flows including Authorization Code Flow and Dynamic Client Registration (DCR).

## Features

### Authorization Code Flow
- Step-by-step OAuth flow testing
- PKCE (Proof Key for Code Exchange) support with optional enable/disable
- Multiple client authentication methods:
  - `client_secret_post` - Send credentials in request body (default)
  - `client_secret_basic` - Send credentials via HTTP Basic Authentication header
- Environment variable configuration
- Interactive configuration editor in the browser
- Detailed console logging and HTTP request/response display

### Dynamic Client Registration (RFC 7591)
- **Auto-Discovery (RFC 8414 / OIDC Discovery)**
  - Automatic endpoint discovery from issuer URL
  - One-click population of all OAuth endpoints
  - Detection of provider capabilities
  - Apply discovered settings to both DCR and Auth Flow
- Programmatic OAuth client registration
- Support for public clients (no client secret)
- Support for confidential clients (with client secret)
- Configurable client metadata:
  - Multiple redirect URIs
  - Grant types and response types
  - Token endpoint authentication methods
  - Optional metadata (logo, policy, TOS URIs)
  - Contact information
  - Software statements (JWT)
- Initial access token support
- One-click credential copy to Authorization Flow

### General Features
- Modern, responsive web interface with tab navigation
- Error handling and debugging
- Full HTTP request/response display
- SSL verification toggle for testing environments

## Quick Start

1. Create virtual environment: `python -m venv oauth_tester_env`
2. Activate it:
   - Windows: `oauth_tester_env\Scripts\activate`
   - macOS/Linux: `source oauth_tester_env/bin/activate`
3. Install dependencies: `pip install -r requirements.txt`
4. Create a `.env` file with your OAuth provider details:
   ```bash
   cp env.example .env
   # Edit .env with your values
   ```
5. Run the application: `python oauth.py`
   - To disable SSL verification: `VERIFY_SSL=false python oauth.py`
6. Open your browser to `http://localhost:5002`

## Configuration

Create a `.env` file in the project root with the following variables:

```env
# Authorization Code Flow Configuration
AUTHORIZATION_URL=https://your-auth-provider.com/oauth/authorize
TOKEN_URL=https://your-auth-provider.com/oauth/token
CLIENT_ID=your-client-id
CLIENT_SECRET=your-client-secret
SCOPES=read write
REDIRECT_URI=http://localhost:5002/callback
USE_PKCE=true
CLIENT_AUTH_METHOD=client_secret_post
VERIFY_SSL=true

# Advanced OAuth Parameters (Optional)
ACR_VALUES=urn:se:curity:authentication:username:username
PROMPT=login
LOGIN_HINT=user@example.com
NONCE=1599046102647-dv4

# Dynamic Client Registration Configuration
REGISTRATION_ENDPOINT=https://your-auth-provider.com/oauth/register
INITIAL_ACCESS_TOKEN=your-initial-access-token-if-required
```

### Environment Variables

#### Authorization Code Flow
- `AUTHORIZATION_URL`: Your OAuth provider's authorization endpoint
- `TOKEN_URL`: Your OAuth provider's token endpoint  
- `CLIENT_ID`: Your OAuth application's client ID
- `CLIENT_SECRET`: Your OAuth application's client secret
- `SCOPES`: Space-separated list of scopes to request
- `REDIRECT_URI`: The redirect URI registered with your OAuth provider
- `USE_PKCE`: Enable/disable PKCE support (default: true)
- `CLIENT_AUTH_METHOD`: Client authentication method - `client_secret_post` or `client_secret_basic` (default: client_secret_post)
- `VERIFY_SSL`: Enable/disable SSL certificate verification (default: true). Set to `false` only for testing if you encounter SSL certificate errors

#### Advanced OAuth Parameters (Optional)
- `ACR_VALUES`: Authentication context class reference (optional)
- `PROMPT`: Prompt parameter (e.g., "login", "consent", "select_account", "none")
- `LOGIN_HINT`: Login hint for pre-filling username (optional)
- `NONCE`: Nonce value for additional security (optional)

#### Dynamic Client Registration
- `REGISTRATION_ENDPOINT`: Your OAuth provider's client registration endpoint (RFC 7591)
- `INITIAL_ACCESS_TOKEN`: Initial access token if required by your OAuth provider (optional)

## Project Structure

```
oauth-test/
├── oauth.py                   # Main Flask application
├── requirements.txt           # Python dependencies
├── env.example               # Example environment configuration
├── readme.md                 # This file - Getting started guide
├── DCR_IMPLEMENTATION.md     # Detailed DCR implementation guide
├── TESTING_GUIDE.md          # Comprehensive testing instructions
├── templates/                # HTML templates
│   ├── base.html            # Base template with common styles
│   ├── home.html            # Authorization Code Flow page
│   ├── dcr.html             # Dynamic Client Registration page
│   ├── success.html         # Success page template
│   └── error.html           # Error page template
└── .env                     # Your environment configuration (create from env.example)
```

## Usage

### Testing Authorization Code Flow

1. Open `http://localhost:5002` in your browser
2. Configure your OAuth provider settings in the "Configuration Editor" section or via `.env` file
3. Click "Start OAuth Flow" to begin the authorization process
4. You'll be redirected to your OAuth provider's login page
5. After authentication, you'll be redirected back with tokens displayed

### Testing Dynamic Client Registration (DCR)

#### Option 1: Auto-Discovery (Recommended)

1. Click on the "Dynamic Client Registration" tab
2. In the "Auto-Discovery" section at the top:
   - Enter your provider's issuer/base URL (e.g., `https://accounts.google.com`)
   - Click "🔍 Discover Endpoints"
   - Review the discovered endpoints and capabilities
   - Click "Apply to DCR Form" to auto-fill the registration form
   - Or click "Apply to Auth Flow" to update Authorization Code Flow settings
3. Review and adjust the pre-filled values as needed
4. Click "Register Client"

#### Option 2: Manual Configuration

1. Click on the "Dynamic Client Registration" tab
2. Scroll to the "Dynamic Client Registration (RFC 7591)" section
3. Enter your provider's registration endpoint URL manually
4. (Optional) Enter an initial access token if your provider requires one
5. Fill in the client metadata:
   - **Client Name**: Human-readable name for your application
   - **Token Endpoint Auth Method**: Choose authentication method
     - `none` - For public clients (SPAs, mobile apps)
     - `client_secret_post` - For confidential clients (credentials in body)
     - `client_secret_basic` - For confidential clients (HTTP Basic Auth)
   - **Redirect URIs**: Add one or more callback URLs
   - **Grant Types**: Select the OAuth grant types you need
   - **Response Types**: Select the response types
   - **Scope**: Space-separated list of scopes
5. (Optional) Add additional metadata like logo URI, policy URI, contacts, etc.
6. Click "Register Client"
7. If successful, use "Copy to Authorization Flow" to test the newly registered client

### Common DCR Use Cases

**Public Client (SPA/Mobile App)**
- Token Endpoint Auth Method: `none`
- Grant Types: `authorization_code`, `refresh_token`
- Response Types: `code`
- Enable PKCE in Authorization Flow settings

**Confidential Client (Backend Service)**
- Token Endpoint Auth Method: `client_secret_post` or `client_secret_basic`
- Grant Types: `authorization_code`, `refresh_token`, `client_credentials`
- Response Types: `code`

**Testing OAuth Providers**
- Use DCR to quickly create test clients
- Verify provider's DCR implementation compliance
- Test different client configurations
- Understand metadata requirements
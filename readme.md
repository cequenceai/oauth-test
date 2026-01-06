# OAuth 2.0 Authorization Code Flow Tester

A simple Flask application to test and debug OAuth 2.0 authorization code flows step by step.

## Features

- Step-by-step OAuth flow testing
- PKCE (Proof Key for Code Exchange) support with optional enable/disable
- Multiple client authentication methods:
  - `client_secret_post` - Send credentials in request body (default)
  - `client_secret_basic` - Send credentials via HTTP Basic Authentication header
- Environment variable configuration
- Interactive configuration editor in the browser
- Detailed console logging and HTTP request/response display
- Modern, responsive web interface
- Error handling and debugging

## Quick Start

1. Create virtual environment: `python -m venv oauth_tester_env`
2. Activate it:
   - Windows: `oauth_tester_env\Scripts\activate`
   - macOS/Linux: `source oauth_tester_env/bin/activate`
3. Install dependencies: `pip install -r requirements.txt`
4. Create a `.env` file with your OAuth provider details
5. Run the application: `python oauth.py`
   - To disable SSL verification: `VERIFY_SSL=false python oauth.py`
6. Open your browser to `http://localhost:5002`

## Configuration

Create a `.env` file in the project root with the following variables:

```env
AUTHORIZATION_URL=https://your-auth-provider.com/oauth/authorize
TOKEN_URL=https://your-auth-provider.com/oauth/token
CLIENT_ID=your-client-id
CLIENT_SECRET=your-client-secret
SCOPES=read write
REDIRECT_URI=http://localhost:5002/callback
USE_PKCE=true
CLIENT_AUTH_METHOD=client_secret_post
VERIFY_SSL=true
ACR_VALUES=urn:se:curity:authentication:username:username
PROMPT=login
LOGIN_HINT=user@example.com
NONCE=1599046102647-dv4
```

### Environment Variables

- `AUTHORIZATION_URL`: Your OAuth provider's authorization endpoint
- `TOKEN_URL`: Your OAuth provider's token endpoint  
- `CLIENT_ID`: Your OAuth application's client ID
- `CLIENT_SECRET`: Your OAuth application's client secret
- `SCOPES`: Space-separated list of scopes to request
- `REDIRECT_URI`: The redirect URI registered with your OAuth provider
- `USE_PKCE`: Enable/disable PKCE support (default: true)
- `CLIENT_AUTH_METHOD`: Client authentication method - `client_secret_post` or `client_secret_basic` (default: client_secret_post)
- `VERIFY_SSL`: Enable/disable SSL certificate verification (default: true). Set to `false` only for testing if you encounter SSL certificate errors
- `ACR_VALUES`: Authentication context class reference (optional)
- `PROMPT`: Prompt parameter (e.g., "login", "consent", "select_account", "none")
- `LOGIN_HINT`: Login hint for pre-filling username (optional)
- `NONCE`: Nonce value for additional security (optional)

## Project Structure

```
auth/
├── oauth.py              # Main Flask application
├── requirements.txt      # Python dependencies
├── templates/            # HTML templates
│   ├── base.html        # Base template with common styles
│   ├── home.html        # Home page template
│   ├── success.html     # Success page template
│   └── error.html       # Error page template
└── .env                 # Environment configuration (create this)
```
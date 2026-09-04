# OAuth 2.0 Flow Tester

A comprehensive Flask application to test and debug OAuth 2.0 flows including Authorization Code Flow, Dynamic Client Registration (DCR), and Client ID Metadata Documents (CIMD).

## Features

### Authorization Code Flow
- Step-by-step OAuth flow testing
- PKCE (Proof Key for Code Exchange) support with optional enable/disable
- Multiple client authentication methods:
  - `client_secret_post` - Send credentials in request body (default)
  - `client_secret_basic` - Send credentials via HTTP Basic Authentication header
  - `none` - Public client, no credentials (PKCE-only / CIMD clients)
- Optional client secret - leave it empty for public clients and it is omitted from token requests
- Custom request parameters for the authorization and/or token endpoints (e.g. `resource`, `audience`), one `key=value` per line, editable from the UI
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

### Client ID Metadata Documents (CIMD)

CIMD (`draft-ietf-oauth-client-id-metadata-document`) lets a client identify itself with a URL instead of a pre-registered client ID: the authorization server fetches the URL and reads the client metadata from the JSON document it returns. The MCP specification (2026-07-28) deprecated DCR in favor of CIMD.

- Serves this tester's own metadata document at `/client-metadata.json`, built live from the current configuration
- One-click "Use as Client ID in Auth Flow" (sets the document URL as `client_id`, auth method `none`, PKCE on, secret cleared)
- **CIMD document validator** - fetch any URL-shaped `client_id` and lint it against the spec: URL shape (HTTPS, path, no fragment/userinfo/dot-segments), HTTP behavior (200, `application/json`, cache headers), and document contents (`client_id` exact-match, registered redirect URIs, no shared-secret auth methods)
- Endpoint discovery reports whether the provider advertises `client_id_metadata_document_supported`

> **Important:** for a remote authorization server to fetch your metadata document, this tester must be reachable over public HTTPS - see [Testing CIMD](#testing-client-id-metadata-documents-cimd) below for the ngrok/cloudflared workflow.

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

# Custom request parameters, one key=value per line (also editable in the UI)
AUTH_EXTRA_PARAMS="resource=https://example.com/mcp"
TOKEN_EXTRA_PARAMS="resource=https://example.com/mcp"

# Dynamic Client Registration Configuration
REGISTRATION_ENDPOINT=https://your-auth-provider.com/oauth/register
INITIAL_ACCESS_TOKEN=your-initial-access-token-if-required

# Client ID Metadata Documents (CIMD)
PUBLIC_BASE_URL=https://your-tunnel.ngrok.app
CIMD_CLIENT_NAME=OAuth 2.0 Flow Tester
```

### Environment Variables

#### Authorization Code Flow
- `AUTHORIZATION_URL`: Your OAuth provider's authorization endpoint
- `TOKEN_URL`: Your OAuth provider's token endpoint  
- `CLIENT_ID`: Your OAuth application's client ID
- `CLIENT_SECRET`: Your OAuth application's client secret (optional - leave empty for public clients)
- `SCOPES`: Space-separated list of scopes to request
- `REDIRECT_URI`: The redirect URI registered with your OAuth provider
- `USE_PKCE`: Enable/disable PKCE support (default: true)
- `CLIENT_AUTH_METHOD`: Client authentication method - `client_secret_post`, `client_secret_basic`, or `none` (default: client_secret_post)
- `VERIFY_SSL`: Enable/disable SSL certificate verification (default: true). Set to `false` only for testing if you encounter SSL certificate errors

#### Advanced OAuth Parameters (Optional)
- `ACR_VALUES`: Authentication context class reference (optional)
- `PROMPT`: Prompt parameter (e.g., "login", "consent", "select_account", "none")
- `LOGIN_HINT`: Login hint for pre-filling username (optional)
- `NONCE`: Nonce value for additional security (optional)
- `AUTH_EXTRA_PARAMS`: Extra parameters for the authorization request, one `key=value` per line (use a double-quoted multi-line value for more than one)
- `TOKEN_EXTRA_PARAMS`: Extra parameters for the token request, same format

#### Dynamic Client Registration
- `REGISTRATION_ENDPOINT`: Your OAuth provider's client registration endpoint (RFC 7591)
- `INITIAL_ACCESS_TOKEN`: Initial access token if required by your OAuth provider (optional)

#### Client ID Metadata Documents (CIMD)
- `PUBLIC_BASE_URL`: Public HTTPS base URL where the authorization server can reach this tester, e.g. an ngrok/cloudflared tunnel. The CIMD document is served at `<PUBLIC_BASE_URL>/client-metadata.json`
- `CIMD_CLIENT_NAME`: `client_name` advertised in the CIMD document (shown on consent screens)

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
│   ├── cimd.html            # Client ID Metadata Documents page
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

### Testing Client ID Metadata Documents (CIMD)

With CIMD there is no registration step: your `client_id` **is** a URL, and the authorization server fetches it to learn your client's metadata. That fetch is the one part that needs to be publicly reachable - the redirect URI can stay on localhost, because the redirect happens in your browser, not server-to-server.

1. Start a tunnel to the tester (only needed for a **remote** authorization server):
   ```bash
   ngrok http 5001
   # or: cloudflared tunnel --url http://localhost:5001
   ```
2. Open the "CIMD" tab and paste the HTTPS tunnel URL into **Public Base URL**
3. Review the generated document preview (redirect URI and scopes come from the Authorization Flow config)
4. Click **"Use as Client ID in Auth Flow"** - this sets the document URL as `client_id`, switches the auth method to `none`, enables PKCE, and clears the client secret
5. Switch to the Authorization Code Flow tab and click "Start OAuth Flow"

Notes:
- Check provider support first: run endpoint discovery on the DCR tab and look for "CIMD (URL client_id): Supported" (`client_id_metadata_document_supported` in the provider metadata)
- A **local** authorization server (e.g. Keycloak in Docker) can fetch `http://localhost:5001/client-metadata.json` directly - no tunnel needed, though strict implementations may still reject a non-HTTPS `client_id`
- You can also host the JSON document on any public HTTPS static host and paste that URL straight into the Client ID field - the `client_id` inside the document must exactly string-match the hosting URL and it must be served as `application/json`
- ngrok's free tier injects a browser interstitial for browser-looking requests; server-to-server fetches normally pass through, but if a provider chokes on it, cloudflared has no interstitial

**Validating a CIMD document:** paste any URL-shaped `client_id` into the validator on the CIMD tab. It fetches the document from the outside - exactly like the AS would - and reports pass/warn/fail per spec rule. Pointing it at your own tunnel URL is a good dry run before involving a real provider.

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
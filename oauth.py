#!/usr/bin/env python3
"""
OAuth 2.0 Authorization Code Flow Tester
A simple Flask app to test and debug OAuth flows step by step
"""

import os
import secrets
import hashlib
import base64
import urllib.parse
import json
from flask import Flask, request, redirect, jsonify, render_template, flash
import requests
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Configuration - Load from environment variables
CONFIG = {
    'auth_url': os.getenv('AUTHORIZATION_URL', 'https://your-auth-provider.com/oauth/authorize'),
    'token_url': os.getenv('TOKEN_URL', 'https://your-auth-provider.com/oauth/token'),
    'client_id': os.getenv('CLIENT_ID', 'your-client-id'),
    'client_secret': os.getenv('CLIENT_SECRET', 'your-client-secret'),
    'scopes': os.getenv('SCOPES', 'refresh_token'),  # Space-separated scopes
    'redirect_uri': os.getenv('REDIRECT_URI', 'http://localhost:5002/callback'),
    'use_pkce': os.getenv('USE_PKCE', 'true').lower() in ('true', '1', 'yes', 'on'),
    'client_auth_method': os.getenv('CLIENT_AUTH_METHOD', 'client_secret_post'),  # client_secret_post or client_secret_basic
    # Additional OAuth parameters for specific providers (like Snowflake)
    'acr_values': os.getenv('ACR_VALUES', ''),
    'prompt': os.getenv('PROMPT', ''),
    'login_hint': os.getenv('LOGIN_HINT', ''),
    'nonce': os.getenv('NONCE', ''),
    'verify_ssl': os.getenv('VERIFY_SSL', 'true').lower() in ('true', '1', 'yes', 'on'),
    # DCR Configuration
    'registration_endpoint': os.getenv('REGISTRATION_ENDPOINT', 'https://your-auth-provider.com/oauth/register'),
    'initial_access_token': os.getenv('INITIAL_ACCESS_TOKEN', '')
}

app = Flask(__name__)
app.secret_key = 'oauth-tester-secret-key'  # For flash messages

# Store for PKCE and state (in production, use proper session storage)
auth_state = {}

# Store discovered metadata (in production, use proper session storage)
discovered_metadata = {}


def generate_pkce_pair():
  """Generate PKCE code verifier and challenge"""
  code_verifier = base64.urlsafe_b64encode(
      secrets.token_bytes(32)).decode('utf-8').rstrip('=')
  code_challenge = base64.urlsafe_b64encode(
      hashlib.sha256(code_verifier.encode('utf-8')).digest()
  ).decode('utf-8').rstrip('=')
  return code_verifier, code_challenge


def render_error_page(error_icon, error_title, error_message, action_text="Try Again", http_data=None):
  """Helper function to render error pages"""
  return render_template('error.html',
                         error_icon=error_icon,
                         error_title=error_title,
                         error_message=error_message,
                         action_text=action_text,
                         http_data=http_data)


@app.route('/')
def home():
  """Home page with instructions"""
  return render_template('home.html', config=CONFIG)


@app.route('/update-config', methods=['POST'])
def update_config():
  """Update configuration from form submission"""
  global CONFIG

  try:
    # Update CONFIG with form data
    CONFIG['auth_url'] = request.form.get('auth_url', CONFIG['auth_url'])
    CONFIG['token_url'] = request.form.get('token_url', CONFIG['token_url'])
    CONFIG['client_id'] = request.form.get('client_id', CONFIG['client_id'])
    CONFIG['client_secret'] = request.form.get(
        'client_secret', CONFIG['client_secret'])
    CONFIG['scopes'] = request.form.get('scopes', CONFIG['scopes'])
    CONFIG['redirect_uri'] = request.form.get(
        'redirect_uri', CONFIG['redirect_uri'])
    CONFIG['use_pkce'] = request.form.get(
        'use_pkce', 'true').lower() in ('true', '1', 'yes', 'on')
    CONFIG['client_auth_method'] = request.form.get(
        'client_auth_method', CONFIG['client_auth_method'])
    CONFIG['verify_ssl'] = request.form.get(
        'verify_ssl', 'true').lower() in ('true', '1', 'yes', 'on')
    CONFIG['acr_values'] = request.form.get('acr_values', '')
    CONFIG['prompt'] = request.form.get('prompt', '')
    CONFIG['login_hint'] = request.form.get('login_hint', '')
    CONFIG['nonce'] = request.form.get('nonce', '')

    flash('Configuration updated successfully!', 'success')

  except Exception as e:
    flash(f'Error updating configuration: {str(e)}', 'error')

  return redirect('/')


@app.route('/auth')
def start_auth():
  """Step 1: Start the authorization flow"""
  print("\n" + "="*50)
  print("STEP 1: Starting Authorization Flow")
  print("="*50)

  # Generate state for CSRF protection
  state = secrets.token_urlsafe(32)

  # Store state
  auth_state['state'] = state

  print(f"Generated state: {state}")
  print(f"PKCE enabled: {CONFIG['use_pkce']}")

  # Build authorization URL parameters
  auth_params = {
      'response_type': 'code',
      'client_id': CONFIG['client_id'],
      'redirect_uri': CONFIG['redirect_uri'],
      'scope': CONFIG['scopes'],
      'state': state
  }

  # Add additional OAuth parameters if configured
  if CONFIG['acr_values']:
    auth_params['acr_values'] = CONFIG['acr_values']
  
  # Validate and add prompt parameter (only valid OAuth prompt values)
  valid_prompts = {'login', 'consent', 'select_account', 'none'}
  if CONFIG['prompt']:
    prompt_value = CONFIG['prompt'].strip()
    # Check if it's a valid prompt value or space-separated combination
    prompt_parts = prompt_value.split()
    if all(part in valid_prompts for part in prompt_parts):
      auth_params['prompt'] = prompt_value
    else:
      print(f"⚠️  Warning: Invalid prompt value '{prompt_value}' - skipping. Valid values: {', '.join(valid_prompts)}")
  
  if CONFIG['login_hint']:
    auth_params['login_hint'] = CONFIG['login_hint']
  if CONFIG['nonce']:
    auth_params['nonce'] = CONFIG['nonce']

  # Add PKCE parameters if enabled
  if CONFIG['use_pkce']:
    # Generate PKCE challenge
    code_verifier, code_challenge = generate_pkce_pair()

    # Store code verifier for later use
    auth_state['code_verifier'] = code_verifier

    # Add PKCE parameters
    auth_params['code_challenge'] = code_challenge
    auth_params['code_challenge_method'] = 'S256'

    print(f"Generated code verifier: {code_verifier}")
    print(f"Generated code challenge: {code_challenge}")
  else:
    print("PKCE disabled - using traditional client secret authentication")

  # Build the URL with proper encoding
  query_string = urllib.parse.urlencode(auth_params)
  authorization_url = f"{CONFIG['auth_url']}?{query_string}"

  print("\nAuthorization URL parameters:")
  print(json.dumps(auth_params, indent=2))
  print(f"\nQuery string: {query_string}")
  print(f"\nFull authorization URL:\n{authorization_url}")

  print("\n✅ Redirecting user to authorization server...")
  return redirect(authorization_url)


@app.route('/callback')
def handle_callback():
  """Step 2: Handle the authorization callback"""
  print("\n" + "="*50)
  print("STEP 2: Handling Authorization Callback")
  print("="*50)

  # Get callback parameters
  code = request.args.get('code')
  state = request.args.get('state')
  error = request.args.get('error')
  error_description = request.args.get('error_description')

  print("Callback parameters received:")
  print(f"- code: {'{}...'.format(code[:20]) if code else 'NOT RECEIVED'}")
  print(f"- state: {state}")
  print(f"- error: {error}")
  print(f"- error_description: {error_description}")

  # Check for errors
  if error:
    print(f"\n❌ Authorization failed:")
    print(f"Error: {error}")
    print(f"Description: {error_description}")
    error_message = f"<strong>Error:</strong> {error}<br><strong>Description:</strong> {error_description or 'No description provided'}"
    return render_error_page("❌", "Authorization Failed", error_message), 400

  # Verify state
  if not state or state != auth_state.get('state'):
    print(f"\n❌ State mismatch - possible CSRF attack")
    print(f"Expected state: {auth_state.get('state')}")
    print(f"Received state: {state}")
    error_message = "<strong>State mismatch detected</strong><br>This could indicate a CSRF attack or session timeout."
    return render_error_page("⚠️", "Security Error", error_message, "Start Over"), 400

  print("✅ State verification passed")

  if not code:
    print("\n❌ No authorization code received")
    error_message = "<strong>No authorization code received</strong><br>The OAuth provider did not return an authorization code."
    return render_error_page("❌", "No Authorization Code", error_message), 400

  print("✅ Authorization code received")

  try:
    # Step 3: Exchange code for tokens
    return exchange_code_for_tokens(code)
  except Exception as e:
    print(f"\n❌ Token exchange failed: {str(e)}")
    error_message = f"<strong>Error:</strong> {str(e)}<br>Check the console logs for more details."
    return render_error_page("❌", "Token Exchange Failed", error_message), 500


def exchange_code_for_tokens(code):
  """Step 3: Exchange authorization code for tokens"""
  print("\n" + "="*50)
  print("STEP 3: Exchanging Code for Tokens")
  print("="*50)

  token_params = {
      'grant_type': 'authorization_code',
      'code': code,
      'redirect_uri': CONFIG['redirect_uri']
  }

  # Determine client authentication method
  auth_method = CONFIG['client_auth_method']
  print(f"Client authentication method: {auth_method}")

  headers = {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Accept': 'application/json'
  }

  if auth_method == 'client_secret_basic':
    # client_secret_basic: Use HTTP Basic Authentication
    # Encode client_id:client_secret as Base64 and send in Authorization header
    credentials = f"{CONFIG['client_id']}:{CONFIG['client_secret']}"
    encoded_credentials = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')
    headers['Authorization'] = f'Basic {encoded_credentials}'
    print("Using client_secret_basic: credentials in Authorization header")
  else:
    # client_secret_post: Send credentials in request body (default)
    token_params['client_id'] = CONFIG['client_id']
    token_params['client_secret'] = CONFIG['client_secret']
    print("Using client_secret_post: credentials in request body")

  # Add PKCE code verifier if PKCE is enabled
  if CONFIG['use_pkce']:
    token_params['code_verifier'] = auth_state.get('code_verifier')
    print("Using PKCE code verifier for token exchange")
  else:
    print("Using traditional client secret authentication (no PKCE)")

  # Log parameters (without exposing client secret)
  log_params = token_params.copy()
  if 'client_secret' in log_params:
    log_params['client_secret'] = '***REDACTED***'
  print("Token request parameters:")
  print(json.dumps(log_params, indent=2))
  
  # Log headers (without exposing credentials)
  log_headers = headers.copy()
  if 'Authorization' in log_headers:
    log_headers['Authorization'] = 'Basic ***REDACTED***'
  print("Request headers:")
  print(json.dumps(log_headers, indent=2))

  print(f"\nMaking token request to: {CONFIG['token_url']}")
  print(f"SSL verification: {CONFIG['verify_ssl']}")

  try:
    response = requests.post(
        CONFIG['token_url'],
        data=token_params,
        headers=headers,
        timeout=30,
        verify=CONFIG['verify_ssl']
    )

    print(f"\n✅ Token request completed!")
    print(f"Status: {response.status_code}")
    print("Response headers:")
    print(json.dumps(dict(response.headers), indent=2))

    if response.status_code == 200:
      tokens = response.json()
      print("\nTokens received:")

      # Log full tokens (browser-based testing tool, no security concerns)
      print(json.dumps(tokens, indent=2))

      # Prepare HTTP request/response data for display
      request_body = response.request.body
      if isinstance(request_body, bytes):
        request_body = request_body.decode('utf-8')
      elif request_body is None:
        request_body = ''

      http_data = {
          'request_method': 'POST',
          'request_url': CONFIG['token_url'],
          'request_headers': dict(response.request.headers),
          'request_body': urllib.parse.unquote(request_body),
          'response_status': response.status_code,
          'response_headers': dict(response.headers),
          'response_body': response.text
      }

      # Prepare token data for template
      token_data = {
          'access_token': tokens.get('access_token', 'Not received'),
          'token_type': tokens.get('token_type', 'Not specified'),
          'expires_in': tokens.get('expires_in', 'Not specified'),
          'refresh_token': tokens.get('refresh_token', 'Not received'),
          'scope': tokens.get('scope', 'Not specified'),
          'http_data': http_data
      }

      return render_template('success.html', tokens=token_data)
    else:
      print(f"\n❌ Token request failed with status {response.status_code}")
      print("Response data:")
      try:
        error_data = response.json()
        print(json.dumps(error_data, indent=2))
        error_message = json.dumps(error_data)
      except:
        print(response.text)
        error_message = response.text

      # Prepare HTTP request/response data for error display
      request_body = response.request.body
      if isinstance(request_body, bytes):
        request_body = request_body.decode('utf-8')
      elif request_body is None:
        request_body = ''

      http_data = {
          'request_method': 'POST',
          'request_url': CONFIG['token_url'],
          'request_headers': dict(response.request.headers),
          'request_body': urllib.parse.unquote(request_body),
          'response_status': response.status_code,
          'response_headers': dict(response.headers),
          'response_body': response.text
      }

      # Format error message nicely
      try:
        error_json = json.loads(error_message)
        formatted_error = f"""
        <div style="text-align: left;">
          <div style="margin-bottom: 1rem;"><strong>HTTP Status:</strong> {response.status_code}</div>
          <div style="margin-bottom: 1rem;"><strong>Error Code:</strong> {error_json.get('error', 'Unknown')}</div>
          <div style="margin-bottom: 1rem;"><strong>Message:</strong> {error_json.get('message', 'No message provided')}</div>
          <div style="margin-bottom: 1rem;"><strong>Success:</strong> {error_json.get('success', 'Unknown')}</div>
        </div>
        """
      except:
        formatted_error = f"""
        <div style="text-align: left;">
          <div style="margin-bottom: 1rem;"><strong>HTTP Status:</strong> {response.status_code}</div>
          <div style="margin-bottom: 1rem;"><strong>Error Details:</strong></div>
          <div style="background-color: #ffffff; border: 1px solid #dee2e6; border-radius: 4px; padding: 0.8rem; font-family: monospace; font-size: 0.85rem; white-space: pre-wrap;">{error_message}</div>
        </div>
        """

      return render_error_page("❌", "Token Request Failed", formatted_error, http_data=http_data), 400

  except requests.exceptions.Timeout:
    print("\n❌ Token request timed out")
    raise Exception("Token request timed out")
  except requests.exceptions.ConnectionError as e:
    print("\n❌ Connection error to token endpoint")
    print(f"Error details: {str(e)}")
    print(f"Error type: {type(e).__name__}")
    if hasattr(e, 'args') and e.args:
      print(f"Error args: {e.args}")
    # Check if it's an SSL error
    if 'SSL' in str(e) or 'certificate' in str(e).lower():
      print("\n⚠️  This might be an SSL certificate verification issue.")
      print("   You may need to verify the certificate or disable SSL verification (not recommended for production).")
    raise Exception(f"Connection error to token endpoint: {str(e)}")
  except requests.exceptions.RequestException as e:
    print(f"\n❌ Request error: {str(e)}")
    raise Exception(f"Request error: {str(e)}")
  except Exception as e:
    print(f"\n❌ Unexpected error: {str(e)}")
    import traceback
    print("Full traceback:")
    traceback.print_exc()
    raise e


@app.route('/test-connectivity')
def test_connectivity():
  """Test connectivity to the token endpoint"""
  import socket
  from urllib.parse import urlparse
  
  try:
    parsed_url = urlparse(CONFIG['token_url'])
    hostname = parsed_url.hostname
    port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
    
    # Test DNS resolution
    try:
      ip = socket.gethostbyname(hostname)
      dns_status = f"✅ DNS resolved: {hostname} -> {ip}"
    except socket.gaierror as e:
      dns_status = f"❌ DNS resolution failed: {str(e)}"
    
    # Test TCP connection
    try:
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.settimeout(5)
      result = sock.connect_ex((hostname, port))
      sock.close()
      if result == 0:
        tcp_status = f"✅ TCP connection successful to {hostname}:{port}"
      else:
        tcp_status = f"❌ TCP connection failed to {hostname}:{port} (error code: {result})"
    except Exception as e:
      tcp_status = f"❌ TCP connection test failed: {str(e)}"
    
    # Test HTTPS request
    try:
      test_response = requests.get(
        CONFIG['token_url'],
        timeout=10,
        verify=CONFIG['verify_ssl']
      )
      https_status = f"✅ HTTPS request successful (status: {test_response.status_code})"
    except requests.exceptions.SSLError as e:
      https_status = f"⚠️  HTTPS SSL error: {str(e)}"
    except requests.exceptions.ConnectionError as e:
      https_status = f"❌ HTTPS connection error: {str(e)}"
    except Exception as e:
      https_status = f"❌ HTTPS request failed: {str(e)}"
    
    return jsonify({
      "token_url": CONFIG['token_url'],
      "hostname": hostname,
      "port": port,
      "dns": dns_status,
      "tcp": tcp_status,
      "https": https_status,
      "ssl_verification": CONFIG['verify_ssl']
    })
  except Exception as e:
    return jsonify({
      "error": str(e),
      "token_url": CONFIG['token_url']
    }), 500


@app.route('/apply-discovery-to-config', methods=['POST'])
def apply_discovery_to_config():
  """Apply discovered endpoints and scopes to Authorization Flow configuration"""
  global CONFIG

  try:
    data = request.json
    authorization_endpoint = data.get('authorization_endpoint')
    token_endpoint = data.get('token_endpoint')
    scopes_supported = data.get('scopes_supported', [])

    if authorization_endpoint:
      CONFIG['auth_url'] = authorization_endpoint
      print(f"Updated authorization endpoint: {authorization_endpoint}")

    if token_endpoint:
      CONFIG['token_url'] = token_endpoint
      print(f"Updated token endpoint: {token_endpoint}")
    
    if scopes_supported:
      scopes = ' '.join(scopes_supported)
      CONFIG['scopes'] = scopes
      print(f"Updated scopes: {scopes}")

    return jsonify({
        'success': True,
        'message': 'Configuration updated successfully'
    })

  except Exception as e:
    print(f"Error applying discovery to config: {str(e)}")
    return jsonify({
        'success': False,
        'error': str(e)
    }), 500


@app.route('/health')
def health_check():
  """Simple health check endpoint"""
  return jsonify({"status": "healthy", "message": "OAuth tester is running"})


@app.route('/dcr')
def dcr_page():
  """Dynamic Client Registration page"""
  return render_template('dcr.html', config=CONFIG, registration_response=None)


@app.route('/register-client', methods=['POST'])
def register_client():
  """Register a new OAuth client using Dynamic Client Registration (RFC 7591)"""
  print("\n" + "="*50)
  print("Dynamic Client Registration (DCR)")
  print("="*50)

  try:
    # Get registration endpoint and access token
    registration_endpoint = request.form.get('registration_endpoint')
    initial_access_token = request.form.get('initial_access_token', '').strip()
    verify_ssl = request.form.get('verify_ssl_dcr', 'true').lower() in ('true', '1', 'yes', 'on')

    # Build client metadata
    client_metadata = {
        'client_name': request.form.get('client_name'),
        'token_endpoint_auth_method': request.form.get('token_endpoint_auth_method')
    }

    # Get redirect URIs (array)
    redirect_uris = request.form.getlist('redirect_uris[]')
    redirect_uris = [uri for uri in redirect_uris if uri.strip()]
    if redirect_uris:
      client_metadata['redirect_uris'] = redirect_uris

    # Get grant types (checkboxes)
    grant_types = request.form.getlist('grant_types')
    if grant_types:
      client_metadata['grant_types'] = grant_types

    # Get response types (checkboxes)
    response_types = request.form.getlist('response_types')
    if response_types:
      client_metadata['response_types'] = response_types

    # Get scope
    scope = request.form.get('scope', '').strip()
    if scope:
      client_metadata['scope'] = scope

    # Optional URIs
    for field in ['client_uri', 'logo_uri', 'policy_uri', 'tos_uri']:
      value = request.form.get(field, '').strip()
      if value:
        client_metadata[field] = value

    # Get contacts (array)
    contacts = request.form.getlist('contacts[]')
    contacts = [contact for contact in contacts if contact.strip()]
    if contacts:
      client_metadata['contacts'] = contacts

    # Software statement (JWT)
    software_statement = request.form.get('software_statement', '').strip()
    if software_statement:
      client_metadata['software_statement'] = software_statement

    print("Registration Endpoint:", registration_endpoint)
    print("Client Metadata:")
    print(json.dumps(client_metadata, indent=2))

    # Prepare headers
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

    # Add initial access token if provided
    if initial_access_token:
      headers['Authorization'] = f'Bearer {initial_access_token}'
      print("Using Initial Access Token")

    # Make registration request
    print(f"\nMaking registration request to: {registration_endpoint}")
    print(f"SSL verification: {verify_ssl}")

    response = requests.post(
        registration_endpoint,
        json=client_metadata,
        headers=headers,
        timeout=30,
        verify=verify_ssl
    )

    print(f"\n✅ Registration request completed!")
    print(f"Status: {response.status_code}")

    # Prepare HTTP request/response data
    request_body = response.request.body
    if isinstance(request_body, bytes):
      request_body = request_body.decode('utf-8')
    elif request_body is None:
      request_body = ''

    http_data = {
        'request_method': 'POST',
        'request_url': registration_endpoint,
        'request_headers': json.dumps(dict(response.request.headers), indent=2),
        'request_body': request_body,
        'response_status': response.status_code,
        'response_headers': json.dumps(dict(response.headers), indent=2),
        'response_body': response.text
    }

    if response.status_code in [200, 201]:
      # Success
      registration_data = response.json()
      print("\nClient registered successfully:")
      print(json.dumps(registration_data, indent=2))

      registration_response = {
          'success': True,
          'client_id': registration_data.get('client_id'),
          'client_secret': registration_data.get('client_secret'),
          'client_id_issued_at': registration_data.get('client_id_issued_at'),
          'client_secret_expires_at': registration_data.get('client_secret_expires_at'),
          'registration_client_uri': registration_data.get('registration_client_uri'),
          'registration_access_token': registration_data.get('registration_access_token'),
          'raw_response': json.dumps(registration_data, indent=2),
          'http_data': http_data
      }

      flash('Client registered successfully!', 'success')
    else:
      # Error
      print(f"\n❌ Registration failed with status {response.status_code}")
      try:
        error_data = response.json()
        print(json.dumps(error_data, indent=2))
        error_message = json.dumps(error_data, indent=2)
      except:
        print(response.text)
        error_message = response.text

      registration_response = {
          'success': False,
          'raw_response': error_message,
          'http_data': http_data
      }

      flash(f'Registration failed: {error_message}', 'error')

    return render_template('dcr.html', config=CONFIG, registration_response=registration_response)

  except requests.exceptions.Timeout:
    print("\n❌ Registration request timed out")
    flash('Registration request timed out', 'error')
    return render_template('dcr.html', config=CONFIG, registration_response=None)
  except requests.exceptions.ConnectionError as e:
    print(f"\n❌ Connection error: {str(e)}")
    flash(f'Connection error: {str(e)}', 'error')
    return render_template('dcr.html', config=CONFIG, registration_response=None)
  except Exception as e:
    print(f"\n❌ Unexpected error: {str(e)}")
    import traceback
    traceback.print_exc()
    flash(f'Error: {str(e)}', 'error')
    return render_template('dcr.html', config=CONFIG, registration_response=None)


@app.route('/copy-to-auth-flow', methods=['POST'])
def copy_to_auth_flow():
  """Copy registered client credentials and endpoints to authorization flow configuration"""
  global CONFIG
  global discovered_metadata

  try:
    # Support both JSON and form data for backwards compatibility
    if request.is_json:
      data = request.json
      client_id = data.get('client_id')
      client_secret = data.get('client_secret', '')
      authorization_endpoint = data.get('authorization_endpoint')
      token_endpoint = data.get('token_endpoint')
    else:
      client_id = request.form.get('client_id')
      client_secret = request.form.get('client_secret', '')
      authorization_endpoint = None
      token_endpoint = None

    if not client_id:
      if request.is_json:
        return jsonify({
            'success': False,
            'error': 'No client ID provided'
        }), 400
      else:
        flash('No client ID to copy', 'error')
        return redirect('/')

    # Update client credentials
    CONFIG['client_id'] = client_id
    print(f"Updated client_id: {client_id}")
    
    if client_secret:
      CONFIG['client_secret'] = client_secret
      print(f"Updated client_secret: ***")
    
    # Use discovered endpoints if not explicitly provided
    if not authorization_endpoint and discovered_metadata.get('authorization_endpoint'):
      authorization_endpoint = discovered_metadata.get('authorization_endpoint')
      print(f"Using stored discovered authorization endpoint")
    
    if not token_endpoint and discovered_metadata.get('token_endpoint'):
      token_endpoint = discovered_metadata.get('token_endpoint')
      print(f"Using stored discovered token endpoint")
    
    # Update endpoints
    endpoints_updated = False
    if authorization_endpoint:
      CONFIG['auth_url'] = authorization_endpoint
      print(f"Updated authorization endpoint: {authorization_endpoint}")
      endpoints_updated = True
    
    if token_endpoint:
      CONFIG['token_url'] = token_endpoint
      print(f"Updated token endpoint: {token_endpoint}")
      endpoints_updated = True
    
    # Update scopes with discovered scopes if available
    scopes_updated = False
    if discovered_metadata.get('scopes_supported'):
      scopes = ' '.join(discovered_metadata.get('scopes_supported'))
      CONFIG['scopes'] = scopes
      print(f"Updated scopes from discovery: {scopes}")
      scopes_updated = True
    
    if request.is_json:
      message = 'Client credentials copied successfully'
      if endpoints_updated:
        message += ' and endpoints updated'
      if scopes_updated:
        message += ' and scopes updated'
      return jsonify({
          'success': True,
          'message': message,
          'updated_endpoints': endpoints_updated,
          'updated_scopes': scopes_updated
      })
    else:
      message = 'Client credentials copied to Authorization Flow!'
      if endpoints_updated:
        message += ' Endpoints also updated!'
      if scopes_updated:
        message += ' Scopes also updated!'
      flash(message, 'success')
      return redirect('/')

  except Exception as e:
    print(f"Error copying to auth flow: {str(e)}")
    if request.is_json:
      return jsonify({
          'success': False,
          'error': str(e)
      }), 500
    else:
      flash(f'Error copying credentials: {str(e)}', 'error')
      return redirect('/')


@app.route('/discover-endpoints', methods=['POST'])
def discover_endpoints():
  """Discover OAuth/OIDC endpoints from issuer URL (RFC 8414 / OIDC Discovery)"""
  print("\n" + "="*50)
  print("OAuth/OIDC Endpoint Discovery")
  print("="*50)

  try:
    issuer_url = request.json.get('issuer_url', '').strip().rstrip('/')
    verify_ssl = request.json.get('verify_ssl', True)
    access_token = request.json.get('access_token', '').strip()

    if not issuer_url:
      return jsonify({
          'success': False,
          'error': 'Issuer URL is required'
      }), 400

    print(f"Issuer URL: {issuer_url}")
    print(f"SSL Verification: {verify_ssl}")
    print(f"Access Token Provided: {bool(access_token)}")

    # Prepare headers
    headers = {'Accept': 'application/json'}
    if access_token:
      headers['Authorization'] = f'Bearer {access_token}'
      print("Using Bearer token for discovery")

    # Try both standard discovery endpoints
    discovery_endpoints = [
        f"{issuer_url}/.well-known/openid-configuration",
        f"{issuer_url}/.well-known/oauth-authorization-server",
        f"{issuer_url}/.well-known/oauth-protected-resource"
    ]

    metadata = None
    discovered_from = None
    last_error = None

    for discovery_url in discovery_endpoints:
      try:
        print(f"\nTrying discovery endpoint: {discovery_url}")
        response = requests.get(
            discovery_url,
            timeout=10,
            verify=verify_ssl,
            headers=headers
        )

        if response.status_code == 200:
          metadata = response.json()
          discovered_from = discovery_url
          print(f"✅ Discovery successful from: {discovery_url}")
          break
        elif response.status_code == 401:
          print(f"❌ Discovery failed with status: 401 (Unauthorized)")
          last_error = "Discovery endpoint requires authentication. Please provide an access token."
          # Check if response has WWW-Authenticate header with hints
          auth_header = response.headers.get('WWW-Authenticate', '')
          if auth_header:
            print(f"WWW-Authenticate: {auth_header}")
        else:
          print(f"❌ Discovery failed with status: {response.status_code}")
          last_error = f"HTTP {response.status_code}: {response.text[:200]}"
      except requests.exceptions.RequestException as e:
        print(f"❌ Discovery failed: {str(e)}")
        last_error = str(e)
        continue

    if metadata:
      # Extract relevant endpoints
      discovered_data = {
          'success': True,
          'discovered_from': discovered_from,
          'issuer': metadata.get('issuer'),
          'authorization_endpoint': metadata.get('authorization_endpoint'),
          'token_endpoint': metadata.get('token_endpoint'),
          'registration_endpoint': metadata.get('registration_endpoint'),
          'userinfo_endpoint': metadata.get('userinfo_endpoint'),
          'jwks_uri': metadata.get('jwks_uri'),
          'scopes_supported': metadata.get('scopes_supported', []),
          'response_types_supported': metadata.get('response_types_supported', []),
          'grant_types_supported': metadata.get('grant_types_supported', []),
          'token_endpoint_auth_methods_supported': metadata.get('token_endpoint_auth_methods_supported', []),
          'registration_endpoint_available': bool(metadata.get('registration_endpoint'))
      }

      # Store discovered metadata in backend for later use
      global discovered_metadata
      discovered_metadata = {
          'authorization_endpoint': metadata.get('authorization_endpoint'),
          'token_endpoint': metadata.get('token_endpoint'),
          'scopes_supported': metadata.get('scopes_supported', [])
      }
      print(f"\n📝 Stored discovered endpoints and scopes in backend for later use")

      print("\nDiscovered metadata:")
      print(json.dumps(discovered_data, indent=2))

      return jsonify(discovered_data)
    else:
      print("\n❌ Discovery failed on all endpoints")
      error_message = last_error if last_error else 'Could not discover endpoints. Provider may not support auto-discovery (RFC 8414/OIDC Discovery).'
      return jsonify({
          'success': False,
          'error': error_message
      }), 404

  except Exception as e:
    print(f"\n❌ Discovery error: {str(e)}")
    import traceback
    traceback.print_exc()
    return jsonify({
        'success': False,
        'error': str(e)
    }), 500


if __name__ == '__main__':
  print("=" * 60)
  print("OAuth 2.0 Authorization Code Flow Tester Started")
  print("=" * 60)
  print("Server running on http://localhost:5002")
  print("Open your browser and go to: http://localhost:5002")
  print("\nConfiguration loaded from environment variables:")
  print(f"- Authorization URL: {CONFIG['auth_url']}")
  print(f"- Token URL: {CONFIG['token_url']}")
  print(f"- Client ID: {CONFIG['client_id']}")
  print(f"- Scopes: {CONFIG['scopes']}")
  print(f"- Redirect URI: {CONFIG['redirect_uri']}")
  print(f"- PKCE Enabled: {CONFIG['use_pkce']}")
  print(f"- Client Auth Method: {CONFIG['client_auth_method']}")
  print(f"- SSL Verification: {'Enabled' if CONFIG['verify_ssl'] else 'Disabled'}")
  print("\nMake sure your .env file is properly configured!")
  print("=" * 60)

  try:
    app.run(
        host='0.0.0.0',
        port=5002,
        debug=True,
        use_reloader=False
    )
  except KeyboardInterrupt:
    print("\n\n=== Server shutting down ===")
  except Exception as e:
    print(f"\n❌ Server error: {str(e)}")

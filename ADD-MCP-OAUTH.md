# ADD-MCP-OAUTH.md

## Plan: Adding OAuth Client Support to Goose for MCP Servers

### Overview

This document outlines a comprehensive plan to add OAuth client support to Goose, enabling it to authenticate with MCP servers that require OAuth authentication. Currently, Goose supports MCP through various transports but lacks built-in OAuth client capabilities similar to tools like Claude Code, Cursor, and MCP Inspector.

### Current State Analysis

#### Existing OAuth Infrastructure in Goose
- **Provider OAuth**: Goose has OAuth implementations for LLM providers (Databricks, GCP, GitHub Copilot) in `crates/goose/src/providers/oauth.rs`
- **MCP Client OAuth**: Basic OAuth framework exists in `crates/mcp-client/src/oauth.rs` with generic service configuration
- **Google Drive MCP**: Specific OAuth implementation using PKCE in `crates/goose-mcp/src/google_drive/oauth_pkce.rs`

#### Gaps Identified
1. **No CLI Integration**: OAuth flows are not integrated into the CLI configuration workflow
2. **No UI Integration**: Desktop app lacks OAuth authentication dialogs
3. **No Unified Configuration**: OAuth credentials are handled separately per extension
4. **Limited Transport Support**: OAuth not integrated with SSE/HTTP transports
5. **No Token Management**: No centralized token refresh and storage

### Architecture Design

#### Core Components

1. **OAuth Manager** (`crates/goose/src/oauth/manager.rs`)
   - Centralized OAuth flow orchestration
   - Token lifecycle management (refresh, expiry)
   - Integration with keyring for secure storage
   - Support for multiple OAuth providers

2. **MCP OAuth Transport** (`crates/mcp-client/src/transport/oauth_transport.rs`)
   - OAuth-aware wrapper for existing transports
   - Automatic token injection and refresh
   - Integration with Bearer token authentication

3. **CLI OAuth Handler** (`crates/goose-cli/src/oauth/`)
   - Interactive OAuth flow for CLI users
   - Browser orchestration for authorization
   - Configuration storage integration

4. **Desktop OAuth Handler** (`ui/desktop/src/oauth/`)
   - Native OAuth dialogs in Electron app
   - Secure token storage in desktop environment
   - OAuth provider configuration UI

#### OAuth Flow Integration Points

1. **Extension Configuration**
   - Detect OAuth requirements during extension setup
   - Prompt for OAuth configuration when needed
   - Store OAuth endpoints and client configuration

2. **Runtime Authentication**
   - Automatic token injection for authenticated requests
   - Background token refresh before expiry
   - Fallback to re-authentication on token failure

3. **Multi-Transport Support**
   - SSE transport with OAuth bearer tokens
   - HTTP transport with OAuth headers
   - StdIO transport with OAuth environment variables

### Implementation Plan

#### Phase 1: Core OAuth Infrastructure (2-3 weeks)

**1.1 Enhanced OAuth Manager**
```rust
// crates/goose/src/oauth/manager.rs
pub struct OAuthManager {
    providers: HashMap<String, OAuthProvider>,
    token_store: Arc<dyn TokenStore>,
    browser_opener: Arc<dyn BrowserOpener>,
}

pub trait TokenStore {
    async fn get_token(&self, provider_id: &str) -> Result<Option<Token>>;
    async fn store_token(&self, provider_id: &str, token: Token) -> Result<()>;
    async fn delete_token(&self, provider_id: &str) -> Result<()>;
}
```

**1.2 OAuth Provider Registry**
```rust
// crates/goose/src/oauth/providers.rs
pub struct OAuthProvider {
    pub discovery_url: Option<String>,
    pub auth_endpoint: String,
    pub token_endpoint: String,
    pub client_registration_endpoint: Option<String>,
    pub client_id: Option<String>,
    pub scopes: Vec<String>,
}
```

**1.3 Token Management**
```rust
// crates/goose/src/oauth/token.rs
#[derive(Serialize, Deserialize)]
pub struct Token {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub scopes: Vec<String>,
}
```

#### Phase 2: Transport Integration (1-2 weeks)

**2.1 OAuth-Aware Transport Wrapper**
```rust
// crates/mcp-client/src/transport/oauth_wrapper.rs
pub struct OAuthTransport<T: Transport> {
    inner: T,
    oauth_manager: Arc<OAuthManager>,
    provider_id: String,
}

impl<T: Transport> Transport for OAuthTransport<T> {
    async fn send(&mut self, message: JsonRpcMessage) -> Result<()> {
        // Inject OAuth token before sending
        let token = self.oauth_manager.get_valid_token(&self.provider_id).await?;
        let authenticated_message = self.add_auth_header(message, &token)?;
        self.inner.send(authenticated_message).await
    }
}
```

**2.2 Transport Factory Updates**
```rust
// crates/mcp-client/src/transport/factory.rs
pub async fn create_transport(
    config: &TransportConfig,
    oauth_manager: Option<Arc<OAuthManager>>,
) -> Result<Box<dyn Transport>> {
    let base_transport = match config.transport_type {
        TransportType::Sse => SseTransport::new(&config.endpoint).await?,
        TransportType::Http => StreamableHttpTransport::new(&config.endpoint)?,
        TransportType::Stdio => StdioTransport::new(&config.command, &config.args)?,
    };

    if let Some(oauth_config) = &config.oauth {
        if let Some(manager) = oauth_manager {
            return Ok(Box::new(OAuthTransport::new(
                base_transport,
                manager,
                oauth_config.provider_id.clone(),
            )));
        }
    }

    Ok(Box::new(base_transport))
}
```

#### Phase 3: CLI Integration (2-3 weeks)

**3.1 OAuth Configuration Commands**
```bash
# New CLI commands
goose configure oauth                    # List OAuth providers
goose configure oauth add <provider>     # Add OAuth provider
goose configure oauth auth <provider>    # Authenticate with provider
goose configure oauth revoke <provider>  # Revoke authentication
```

**3.2 Extension Configuration Enhancement**
```rust
// crates/goose-cli/src/commands/configure.rs
async fn configure_oauth_extension(
    extension_config: &mut ExtensionConfig,
    oauth_manager: &OAuthManager,
) -> Result<()> {
    // Detect if extension requires OAuth
    if let Some(oauth_discovery) = detect_oauth_capability(&extension_config.endpoint).await? {
        println!("🔐 This extension requires OAuth authentication");
        
        // Register OAuth provider if not exists
        let provider_id = format!("{}-oauth", extension_config.name);
        oauth_manager.register_provider(provider_id.clone(), oauth_discovery).await?;
        
        // Perform OAuth flow
        println!("Starting OAuth authentication...");
        oauth_manager.authenticate(&provider_id).await?;
        
        // Update extension config
        extension_config.oauth = Some(OAuthConfig {
            provider_id,
            required_scopes: oauth_discovery.default_scopes,
        });
    }
}
```

**3.3 Interactive OAuth Flow**
```rust
// crates/goose-cli/src/oauth/flow.rs
pub struct CliOAuthFlow {
    callback_server: Option<CallbackServer>,
    browser_opener: BrowserOpener,
}

impl CliOAuthFlow {
    pub async fn execute(&mut self, provider: &OAuthProvider) -> Result<Token> {
        // Start local callback server
        let callback_server = CallbackServer::start().await?;
        let callback_url = callback_server.url();
        
        // Build authorization URL
        let auth_url = provider.build_auth_url(&callback_url)?;
        
        // Open browser
        println!("🌐 Opening browser for authentication...");
        self.browser_opener.open(&auth_url)?;
        
        // Wait for callback
        let auth_code = callback_server.wait_for_callback().await?;
        
        // Exchange code for token
        provider.exchange_code_for_token(auth_code, &callback_url).await
    }
}
```

#### Phase 4: Desktop App Integration (3-4 weeks)

**4.1 OAuth Configuration UI**
```typescript
// ui/desktop/src/oauth/OAuthConfigDialog.tsx
export const OAuthConfigDialog: React.FC<{
  extension: Extension;
  onAuthenticated: (token: OAuthToken) => void;
}> = ({ extension, onAuthenticated }) => {
  const [authState, setAuthState] = useState<'idle' | 'authenticating' | 'complete'>('idle');
  
  const handleAuthenticate = async () => {
    setAuthState('authenticating');
    try {
      const token = await window.goose.oauth.authenticate(extension.oauthConfig);
      onAuthenticated(token);
      setAuthState('complete');
    } catch (error) {
      console.error('OAuth authentication failed:', error);
      setAuthState('idle');
    }
  };

  return (
    <Dialog open>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Authenticate with {extension.name}</DialogTitle>
          <DialogDescription>
            This extension requires OAuth authentication to access external services.
          </DialogDescription>
        </DialogHeader>
        
        {authState === 'idle' && (
          <Button onClick={handleAuthenticate}>
            🔐 Start Authentication
          </Button>
        )}
        
        {authState === 'authenticating' && (
          <div>
            <Spinner />
            <p>Please complete authentication in your browser...</p>
          </div>
        )}
        
        {authState === 'complete' && (
          <div>
            <CheckIcon />
            <p>Authentication successful!</p>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
};
```

**4.2 Native OAuth Window**
```typescript
// ui/desktop/src/oauth/OAuthWindow.ts
export class OAuthWindow {
  private window: BrowserWindow | null = null;
  
  async authenticate(provider: OAuthProvider): Promise<OAuthToken> {
    return new Promise((resolve, reject) => {
      this.window = new BrowserWindow({
        width: 500,
        height: 700,
        webPreferences: {
          nodeIntegration: false,
          contextIsolation: true,
        },
      });
      
      // Handle navigation to capture auth code
      this.window.webContents.on('will-navigate', (event, url) => {
        if (url.startsWith(provider.redirectUri)) {
          const authCode = this.extractAuthCode(url);
          if (authCode) {
            this.exchangeCodeForToken(provider, authCode)
              .then(resolve)
              .catch(reject);
            this.close();
          }
        }
      });
      
      // Load OAuth authorization URL
      this.window.loadURL(provider.authorizationUrl);
    });
  }
}
```

**4.3 IPC Bridge for OAuth**
```typescript
// ui/desktop/src/preload.ts
contextBridge.exposeInMainWorld('goose', {
  oauth: {
    authenticate: (config: OAuthConfig): Promise<OAuthToken> =>
      ipcRenderer.invoke('oauth-authenticate', config),
    getStoredToken: (providerId: string): Promise<OAuthToken | null> =>
      ipcRenderer.invoke('oauth-get-token', providerId),
    revokeToken: (providerId: string): Promise<void> =>
      ipcRenderer.invoke('oauth-revoke-token', providerId),
  },
});
```

#### Phase 5: Configuration & Storage (1-2 weeks)

**5.1 OAuth Configuration Schema**
```yaml
# Extension configuration with OAuth
extensions:
  - name: "square-remote"
    type: "sse"
    endpoint: "https://mcp.squareup.com/sse"
    oauth:
      provider_id: "square-oauth"
      required_scopes: ["payments", "catalog"]
      discovery_url: "https://mcp.squareup.com/.well-known/oauth-authorization-server"

oauth_providers:
  square-oauth:
    name: "Square OAuth"
    discovery_url: "https://mcp.squareup.com/.well-known/oauth-authorization-server"
    client_id: "auto-registered"  # Will be dynamically registered
    scopes: ["payments", "catalog", "customers"]
    redirect_uri: "http://localhost:8020"
```

**5.2 Secure Token Storage**
```rust
// crates/goose/src/oauth/storage.rs
pub struct KeyringTokenStore {
    keyring: Arc<Keyring>,
}

impl TokenStore for KeyringTokenStore {
    async fn store_token(&self, provider_id: &str, token: Token) -> Result<()> {
        let key = format!("goose-oauth-{}", provider_id);
        let token_json = serde_json::to_string(&token)?;
        self.keyring.set_password(&key, "oauth-token", &token_json)?;
        Ok(())
    }
    
    async fn get_token(&self, provider_id: &str) -> Result<Option<Token>> {
        let key = format!("goose-oauth-{}", provider_id);
        match self.keyring.get_password(&key, "oauth-token") {
            Ok(token_json) => {
                let token: Token = serde_json::from_str(&token_json)?;
                Ok(Some(token))
            }
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}
```

### Configuration Examples

#### Example 1: Square MCP with OAuth
```yaml
# Via CLI configuration
extensions:
  - name: "square-mcp"
    type: "sse"
    endpoint: "https://mcp.squareup.com/sse"
    oauth:
      provider_id: "square"
      auto_discover: true
      scopes: ["payments", "catalog"]
```

#### Example 2: Custom OAuth Provider
```yaml
oauth_providers:
  custom-service:
    name: "Custom Service OAuth"
    auth_endpoint: "https://auth.example.com/oauth/authorize"
    token_endpoint: "https://auth.example.com/oauth/token"
    client_id: "goose-client"
    scopes: ["read", "write"]
    redirect_uri: "http://localhost:8020"
```

### Testing Strategy

#### Unit Tests
- OAuth flow components
- Token management and refresh logic
- Transport integration
- Configuration parsing

#### Integration Tests
- End-to-end OAuth flows
- CLI configuration workflows
- Desktop app authentication
- Multi-provider scenarios

#### Security Testing
- Token storage security
- PKCE implementation validation
- State parameter validation
- Token refresh race conditions

### Migration Plan

#### Backward Compatibility
- Existing MCP configurations continue to work
- OAuth is opt-in for new extensions
- Graceful fallback for non-OAuth extensions

#### Migration Steps
1. **Phase 1**: Deploy core OAuth infrastructure
2. **Phase 2**: Update CLI with OAuth support
3. **Phase 3**: Release desktop app OAuth features
4. **Phase 4**: Update documentation and examples
5. **Phase 5**: Migrate existing OAuth extensions (Google Drive MCP)

### Security Considerations

#### Token Security
- Use system keyring for token storage
- Implement token encryption at rest
- Secure token transmission (HTTPS only)
- Token rotation and lifecycle management

#### OAuth Security
- PKCE implementation for public clients
- State parameter validation
- Redirect URI validation
- Scope limitation and validation

#### Network Security
- TLS/HTTPS enforcement
- Certificate validation
- Request signing where supported
- Rate limiting and retry logic

### Documentation Requirements

#### User Documentation
- OAuth setup guides per provider
- Troubleshooting common OAuth issues
- Security best practices
- Configuration examples

#### Developer Documentation
- OAuth provider integration guide
- Custom OAuth provider implementation
- Extension OAuth configuration
- API documentation for OAuth components

### Success Metrics

#### Functional Metrics
- OAuth-enabled extensions working out-of-box
- Successful token refresh without user intervention
- CLI and desktop app OAuth parity
- Support for major OAuth providers

#### Security Metrics
- No credential leakage in logs or storage
- Secure token storage validation
- OAuth flow security audit pass
- Vulnerability assessment completion

#### User Experience Metrics
- OAuth setup completion rate
- Time to first successful authentication
- User error rates during OAuth flows
- Support ticket reduction for auth issues

### Future Enhancements

#### Advanced OAuth Features
- OAuth 2.1 support
- Device flow for headless environments
- JWT-based authentication
- Multi-tenant OAuth configurations

#### Enterprise Features
- SAML/OIDC integration
- Corporate proxy support
- Centralized OAuth policy management
- Audit logging for OAuth events

#### Developer Features
- OAuth provider SDK
- Testing utilities for OAuth flows
- OAuth debugging tools
- Provider configuration validation

### Conclusion

This plan provides a comprehensive approach to adding OAuth client support to Goose, enabling seamless integration with OAuth-protected MCP servers. The phased implementation ensures backward compatibility while providing a robust, secure, and user-friendly authentication experience across both CLI and desktop interfaces.

The implementation leverages existing OAuth infrastructure in Goose while extending it to support the specific requirements of MCP authentication, following industry best practices for OAuth client implementation and security.
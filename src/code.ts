import { generateRandomString, base64urlEncode, sha256, base64urlDecode } from "./utils.js";

/**
 * The result of handling the state in the URL.
 * - "completed" means the authentication process has finished successfully;
 * - "nothing" means that there was no state in the URL to handle;
 * - "invalid" means that there was a mismatch between the stored state and URL params;
 * - "error" means there was an error.
 */
export interface HandleStateResult {
  status: "completed" | "nothing" | "invalid" | "error";
  msg: string;
}

/**
 * A typical JWT payload. Probably not really correct.
 */
interface JWTPayload {
  exp: number;
  iat: number;
  auth_time: number;
  jti: string;
  iss: string;
  sub: string;
  typ: string;
  azp: string;
  nonce: string;
  session_state: string;
  scope: string;
  sid: string;
  email: string;
}

/**
 * The well known configuration for an OpenID Connect provider
 */
export interface WellKnownConfig {
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  // Logout endpoint if existing
  logout_endpoint?: string;
}

/**
 * The options for the CodeOICClient
 */
export interface CodeOICClientOptions {
  clientId: string;
  clientSecret?: string;
  scopes?: string[];
  accessType?: string;
  redirectUri: string;
  pkce?: boolean;
  prompt?: string;
  checkToken?: (token: string) => Promise<boolean>;
  debug?: boolean;
}

/**
 * See https://www.oauth.com/oauth2-servers/authorization/the-authorization-request/
 */
type AuthorizationRequest = {
  response_type: "code";
  client_id: string;
  redirect_uri: string;
  scope: string;
  state: string;
  nonce: string;
  prompt?: string;
  code_challenge?: string;
  code_challenge_method?: string;
  access_type?: string;
};

/**
 * https://www.oauth.com/oauth2-servers/device-flow/token-request/
 */
type TokenRequest = {
  grant_type: "authorization_code";
  client_id: string;
  client_secret?: string;
  redirect_uri: string;
  code: string;
  code_verifier?: string;
};

type RefreshTokenRequest = {
  grant_type: "refresh_token";
  client_id: string;
  client_secret?: string;
  refresh_token: string;
};

type TokenResponse = {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  id_token: string;
};

export class CodeOIDCClient {
  constructor(
    private options: CodeOICClientOptions,
    private wellKnown: WellKnownConfig,
  ) {}

  private lget(key: string, remove = false): string | null {
    const k = `oidcjs_${key}`;
    const v = localStorage.getItem(k);
    if (v === "undefined") {
      return undefined;
    }
    if (remove) {
      localStorage.removeItem(k);
    }
    return v;
  }

  private lset(key: string, value: string) {
    localStorage.setItem(`oidcjs_${key}`, value);
  }

  /**
   * Clear all localstorage keys used by this object.
   */
  lclear() {
    const keys: string[] = [];
    for (const key in localStorage) {
      if (key.startsWith("oidcjs_")) {
        keys.push(key);
      }
    }
    for (const key of keys) {
      localStorage.removeItem(key);
    }
  }

  /**
   *
   * @param search The URLSearchParams of the current URL
   * @return once the state has been handled
   * @throws
   */
  async handleStateIfInURL(search: URLSearchParams): Promise<HandleStateResult> {
    const debug = this.options.debug;

    // see https://www.oauth.com/oauth2-servers/authorization/the-authorization-response/
    const state = search.get("state");
    if (!state) {
      if (debug) {
        console.log("No state in URL");
      }
      return {
        status: "nothing",
        msg: "No state in URL",
      };
    }

    const storedState = this.lget("state", true);

    if (debug) {
      console.log("Handling state if in URL...");
    }
    if (!storedState) {
      return {
        status: "invalid",
        msg: "No stored state",
      };
    }

    const error = search.get("error");
    if (error) {
      return {
        status: "error",
        msg: search.get("error_description"),
      };
    }

    const code = search.get("code");
    if (!code) {
      return {
        status: "invalid",
        msg: "No code in URL",
      };
    }
    if (state !== storedState) {
      return {
        status: "error",
        msg: "State does not match",
      };
    }

    try {
      await this.retrieveAndStoreTokens(code);
      return {
        status: "completed",
        msg: "Authentication procedure finished",
      };
    } catch (e) {
      return {
        status: "error",
        msg: e.toString(),
      };
    }
  }

  /**
   * Retrieve the access and refresh tokens and store them in the local storage.
   * Additionnaly, check validity of the token with the provided checkToken function.
   * @param code The code from the authorization response
   * @return once retrieval is complete
   */
  private async retrieveAndStoreTokens(code: string): Promise<string> {
    const debug = this.options.debug;
    if (debug) {
      console.log("Retrieving and storing tokens...");
    }
    const params: TokenRequest = {
      grant_type: "authorization_code",
      client_id: this.options.clientId,
      redirect_uri: this.options.redirectUri,
      code: code,
    };
    if (this.options.clientSecret) {
      params.client_secret = this.options.clientSecret;
    }
    if (this.options.pkce) {
      if (debug) {
        console.log("Using PKCE");
      }
      const code_verifier = this.lget("code_verifier") || undefined;
      if (!code_verifier) {
        return Promise.reject("No code_verifier found");
      }
      params.code_verifier = code_verifier;
    }
    return this.doTokenQuery(params);
  }

  private async doTokenQuery(params: TokenRequest | RefreshTokenRequest): Promise<string> {
    const response = await fetch(this.wellKnown.token_endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      mode: "cors",
      credentials: "omit",
      body: new URLSearchParams(params),
    });
    const data: TokenResponse = await response.json();
    const { access_token, id_token, refresh_token, expires_in } = data;
    if (!access_token || !id_token) {
      return Promise.reject("Did not reveive id or access tokens");
    }
    if (!refresh_token) {
      console.log("We received no refresh token");
    }
    if (this.options.checkToken) {
      const valid = await this.options.checkToken(access_token);
      if (!valid) {
        return Promise.reject("Token is not valid");
      }
    }
    const expiresAt = Date.now() / 1000 + (expires_in ? expires_in : 3_600 * 24 * 365 * 5);
    this.lset("access_token", access_token);
    this.lset("refresh_token", refresh_token);
    this.lset("access_token_expires_at", expiresAt.toString());
    this.lset("id_token", id_token);
    if (this.options.debug) {
      console.log("doTokenQuery", access_token);
    }
    return access_token;
  }

  /**
   * Start a log in process.
   * This will redirect to the SSO and back to the provided redirect URI.
   */
  async createAuthorizeAndUpdateLocalStorage(scopes?: string[]): Promise<string> {
    const debug = this.options.debug;
    if (debug) {
      console.log("Starting loging process");
    }
    const nonce = generateRandomString(16);
    const state = generateRandomString(16);
    this.lset("state", state);
    const params: AuthorizationRequest = {
      response_type: "code",
      client_id: this.options.clientId,
      redirect_uri: this.options.redirectUri,
      scope: (scopes || this.options.scopes).join(" "),
      state: state,
      nonce: nonce,
    };
    if (this.options.prompt) {
      params.prompt = this.options.prompt;
    }
    if (this.options.accessType) {
      params.access_type = this.options.accessType;
    }
    if (this.options.pkce) {
      if (debug) {
        console.log("Using a PKCE authorization");
      }
      // See https://www.oauth.com/oauth2-servers/pkce/authorization-request/
      const code_verifier = generateRandomString(128);
      this.lset("code_verifier", code_verifier);
      const hash = await sha256(code_verifier);
      const codeChallenge = base64urlEncode(hash);
      params.code_challenge = codeChallenge;
      params.code_challenge_method = "S256";
    }

    const authorizeUrl = new URL(this.wellKnown.authorization_endpoint);
    for (const [k, v] of Object.entries(params)) {
      authorizeUrl.searchParams.append(k, v);
    }
    return authorizeUrl.toString();
  }

  /**
   *
   * @param token A well-formed token
   * @return the parsed payload or undefined if the token is not well-formed
   * @throws if not a well formed JWT token or not in a secured browsing context
   */
  parseJwtPayload(token: string): JWTPayload {
    if (!token) {
      return null;
    }
    try {
      const base64Url = token.split(".")[1];
      const buffer = base64urlDecode(base64Url);
      const decoder = new TextDecoder();
      const payload = decoder.decode(buffer);
      return JSON.parse(payload);
    } catch (e) {
      console.error("Could not parse token", token);
      throw e;
    }
  }

  private async refreshToken(refreshToken: string): Promise<string> {
    const params: RefreshTokenRequest = {
      grant_type: "refresh_token",
      client_id: this.options.clientId,
      refresh_token: refreshToken,
    };
    if (this.options.clientSecret) {
      params.client_secret = this.options.clientSecret;
    }
    return this.doTokenQuery(params);
  }

  /**
   * @deprecated all tokens are not JWT
   * @param token
   * @returns
   */
  isActiveToken(token: string): boolean {
    const payload = this.parseJwtPayload(token);
    if (!payload) {
      return false;
    }

    return this.isInsideValidityPeriod(payload.exp, 30);
  }

  protected isInsideValidityPeriod(expiration: number, leeway = 30): boolean {
    // Substract 30 seconds to the token expiration time
    // to eagerly renew the token and give us some margin.
    // This is necessary to account of clock discrepency between client and server.
    // Ideally, the server also tolerate some leeway.
    return expiration - leeway > Date.now() / 1000;
  }

  async getActiveToken(): Promise<string> {
    const expiresAt = this.lget("access_token_expires_at");
    const accessToken = this.lget("access_token");
    const debug = this.options.debug;
    if (!accessToken) {
      if (debug) {
        console.log("No access token found");
      }
      return "";
    }
    if (!expiresAt) {
      if (debug) {
        console.log("No expires_at found");
      }
      return "";
    }

    // Access tokens are not guaranteed to be JWT so are not inspectable.
    // Instead, we use the companion expires_in property. Note that it may still fail if the token was revoked.
    if (this.isInsideValidityPeriod(Number.parseInt(expiresAt))) {
      return accessToken;
    }
    const refreshToken = this.lget("refresh_token");
    if (!refreshToken) {
      if (debug) {
        console.log("No refresh token found");
      }
      return "";
    }
    // There is no reliable way to check refresh token validity in advance, so just try using it.
    return this.refreshToken(refreshToken);
  }

  getActiveIdToken(): string {
    return this.lget("id_token");
  }

  logout(document: Document) {
    if (!this.wellKnown.logout_endpoint) {
      console.log("No logout endpoint");
      this.lclear();
      return;
    }
    const activeIdToken = this.getActiveIdToken();
    if (!activeIdToken) {
      console.error("No active id token found");
      this.lclear();
      return;
    }
    const newLocation = new URL(this.wellKnown.logout_endpoint);
    const sp = newLocation.searchParams;
    sp.append("post_logout_redirect_uri", this.options.redirectUri);
    sp.append("client_id", this.options.clientId);
    sp.append("id_token_hint", activeIdToken);
    this.lclear();
    document.location = newLocation.toString();
  }

  /**
   *
   * @param token Valid access token
   * @return the userinfo response
   */
  // biome-ignore lint/suspicious/noExplicitAny: User info have any shape
  async retrieveUserInfo(token: string): Promise<any> {
    const response = await fetch(this.wellKnown.userinfo_endpoint, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });
    return response.json();
  }
}

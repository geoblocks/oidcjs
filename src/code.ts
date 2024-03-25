import { generateRandomString, base64urlEncode, sha256, base64urlDecode } from "./utils";

/**
 * The result of handling the state in the URL.
 * - "finished" means the authentication process has finished successfully;
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
}

/**
 * The options for the CodeOICClient
 */
export interface CodeOICClientOptions {
  clientId: string;
  redirectUri: string;
  pkce?: boolean;
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
  code_challenge?: string;
  code_challenge_method?: string;
};

/**
 * https://www.oauth.com/oauth2-servers/device-flow/token-request/
 */
type TokenRequest = {
  grant_type: "authorization_code";
  client_id: string;
  redirect_uri: string;
  code: string;
  code_verifier?: string;
};

type RefreshTokenRequest = {
  grant_type: "refresh_token";
  client_id: string;
  refresh_token: string;
};

type TokenResponse = {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token: string;
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
    for (const key in keys) {
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
    const { access_token, id_token, refresh_token } = data;
    if (!access_token || !refresh_token || !id_token) {
      return Promise.reject("Did not reveive tokens");
    }
    if (this.options.checkToken) {
      const valid = await this.options.checkToken(access_token);
      if (!valid) {
        return Promise.reject("Token is not valid");
      }
    }
    this.lset("access_token", access_token);
    this.lset("refresh_token", refresh_token);
    this.lset("id_token", id_token);
    return access_token;
  }

  /**
   * Start a log in process.
   * This will redirect to the SSO and back to the provided redirect URI.
   */
  async createAuthorizeAndUpdateLocalStorage(scopes: string[]): Promise<string> {
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
      scope: scopes.join(" "),
      state: state,
      nonce: nonce,
    };
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

    const authorizeUrl = `${this.wellKnown.authorization_endpoint}?${new URLSearchParams(params)}`;
    return authorizeUrl;
  }

  /**
   *
   * @param token A well-formed token
   * @return the parsed payload or undefined if the token is not well-formed
   */
  parseJwtPayload(token: string): JWTPayload {
    try {
      const base64Url = token.split(".")[1];
      const buffer = base64urlDecode(base64Url);
      const decoder = new TextDecoder();
      const payload = decoder.decode(buffer);
      return JSON.parse(payload);
    } catch {
      return undefined;
    }
  }

  private async refreshToken(refreshToken: string): Promise<string> {
    const params: RefreshTokenRequest = {
      grant_type: "refresh_token",
      client_id: this.options.clientId,
      refresh_token: refreshToken,
    };
    return this.doTokenQuery(params);
  }

  isActive(token: string): boolean {
    const payload = this.parseJwtPayload(token);
    if (!payload) {
      return false;
    }
    // Add 30 seconds to the expiration time to account for clock skew
    return payload.exp + 30 > Date.now() / 1000;
  }

  async getActiveToken(): Promise<string> {
    const accessToken = this.lget("access_token");
    const debug = this.options.debug;
    if (!accessToken) {
      if (debug) {
        console.log("No access token found");
      }
      return "";
    }
    if (this.isActive(accessToken)) {
      return accessToken;
    }
    const refreshToken = this.lget("refresh_token");
    if (!refreshToken) {
      if (debug) {
        console.log("No refresh token found");
      }
      return "";
    }
    if (this.isActive(refreshToken)) {
      return this.refreshToken(refreshToken);
    }
    return "";
  }
}

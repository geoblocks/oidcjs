import { generateRandomString, base64urlEncode, sha256, base64urlDecode } from "./utils";

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

export class CodeOICClient {
  constructor(
    private options: CodeOICClientOptions,
    private wellKnown: WellKnownConfig,
  ) {}

  private lget(key: string): string | null {
    return localStorage.getItem(`oicjs_${key}`);
  }

  private lset(key: string, value: string) {
    localStorage.setItem(`oicjs_${key}`, value);
  }

  /**
   * Clear all localstorage keys used by this object.
   */
  lclear() {
    const keys: string[] = [];
    for (const key in localStorage) {
      if (key.startsWith("oicjs_")) {
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
   */
  async handleStateIfInURL(search: URLSearchParams) {
    const storedState = this.lget("state");
    const debug = this.options.debug;
    if (debug) {
      console.log("Handling state if in URL...");
    }
    if (!storedState) {
      if (debug) {
        console.error("No stored state");
      }
      return;
    }

    // see https://www.oauth.com/oauth2-servers/authorization/the-authorization-response/
    const state = search.get("state");
    const code = search.get("code");
    if (!state) {
      if (debug) {
        console.error("No state in URL");
      }
      return;
    }
    if (!code) {
      if (debug) {
        console.error("No code in URL");
      }
      return;
    }
    if (state !== storedState) {
      if (debug) {
        console.error("State does not match", state, storedState);
      }
      return;
    }

    await this.retrieveAndStoreTokens(code);

    // clear stored state
    this.lset("state", "");
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
  async createAuthorizeAndUpdateLocalStorage(): Promise<string> {
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
      scope: "openid",
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

  parseJwtPayload(token: string): JWTPayload {
    const base64Url = token.split(".")[1];
    const buffer = base64urlDecode(base64Url);
    const decoder = new TextDecoder();
    const payload = decoder.decode(buffer);
    return JSON.parse(payload);
  }

  private async refreshToken(refreshToken: string): Promise<string> {
    const params: RefreshTokenRequest = {
      grant_type: "refresh_token",
      client_id: this.options.clientId,
      refresh_token: refreshToken,
    };
    return this.doTokenQuery(params);
  }

  async getActiveToken(): Promise<string> {
    // const token = this.lget("access_token");
    // if (!token) {
    //   return Promise.reject("No token found");
    // }
    // let payload = this.parseJwtPayload(token);
    // const exp = payload.exp;
    // if (exp + 30 < Date.now() / 1000) {
    //   return token;
    // }
    const refreshToken = this.lget("refresh_token");
    if (!refreshToken) {
      return Promise.reject("No refresh token found");
    }
    return this.refreshToken(refreshToken);
  }
}

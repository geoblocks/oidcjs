import CodeOIDCClient from "./lib/index.js";

// These are test envs
const envs = {
  local: {
    wellKnown: {
      authorization_endpoint: "http://localhost:8080/oauth/v2/authorize",
      token_endpoint: "http://localhost:8080/oauth/v2/token",
      userinfo_endpoint: "http://localhost:8080/oidc/v1/userinfo",
    },
    options: {
      redirectUri: "http://localhost:8000/",
      clientId: "297227398095634709",
      scopes: ["openid", "offline_access", "urn:zitadel:iam:user:metadata"],
      prompt: "login",
      pkce: true,
      debug: true,
    },
  },
  google: {
    wellKnown: {
      // See https://developers.google.com/identity/openid-connect/openid-connect#discovery
      authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth",
      token_endpoint: "https://oauth2.googleapis.com/token",
    },
    options: {
      // This is the URI that keycloak will use to finish the authentication process
      // It must be an exact URL, not a prefix.
      redirectUri: "http://localhost:8000/",
      // The client ID is provided by your SSO server
      clientId: "494959279176-2tq0hm0i4u36c60olsnmng9sfpeqs8m1.apps.googleusercontent.com",
      // PKCE is an optional security feature, that must be enabled in your SSO server.
      clientSecret: "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",
      scopes: ["openid"],
      accessType: "offline",
      pkce: false,
      debug: true,
    },
  },
  gmfngv: {
    wellKnown: {
      authorization_endpoint: "https://sso.geomapfish-demo.prod.apps.gs-ch-prod.camptocamp.com/oauth/v2/authorize",
      token_endpoint: "https://sso.geomapfish-demo.prod.apps.gs-ch-prod.camptocamp.com/oauth/v2/token",
      userinfo_endpoint: "https://sso.geomapfish-demo.prod.apps.gs-ch-prod.camptocamp.com/oidc/v1/userinfo",
    },
    options: {
      redirectUri: "http://localhost:8000/",
      clientId: "294600834753305656",
      scopes: ["openid", "offline_access"],
      pkce: true,
      debug: true,
    },
  },
  c2cngv: {
    wellKnown: {
      authorization_endpoint: "https://sso.idm.camptocamp.com/auth/realms/sandbox/protocol/openid-connect/auth",
      token_endpoint: "https://sso.idm.camptocamp.com/auth/realms/sandbox/protocol/openid-connect/token",
    },
    options: {
      redirectUri: "http://localhost:8000/",
      clientId: "ngv-labs",
      scopes: ["openid", "email", "profile"],
      pkce: true,
      debug: true,
    },
  },
};

/**
 * For this demo we support connecting to integration and production Keycloaks.
 * In a real application you can directly instantiate the client with the correct configuration.
 * @param {string} envName
 * @return {CodeOICClient}
 */
function createClient(envName) {
  const envConfig = envs[envName];
  const client = new CodeOIDCClient(envConfig.options, envConfig.wellKnown);

  return client;
}

console.log("Env from storage", localStorage.getItem("env"));
let envName = localStorage.getItem("env") || "gmfngv";
const envSelect = document.querySelector("#env");
for (const key in envs) {
  const option = document.createElement("option");
  option.value = key;
  option.text = key;
  option.selected = key === envName;
  envSelect.appendChild(option);
}

let client = createClient(envName);
window.client = client;
console.log("For the demo, access the client from window.client");
document.querySelector("#env").addEventListener("change", (evt) => {
  envName = evt.target.selectedOptions[0].value;
  localStorage.setItem("env", envName);
  client = createClient(envName);
  console.log("Created client for", envName);
});

try {
  // When the demo starts, try to finish the login process
  const preLogoutUrl = localStorage.getItem("app_preLogoutURL");
  if (preLogoutUrl) {
    localStorage.removeItem("app_preLogoutURL");
    document.location = preLogoutUrl;
  } else {
    await client.handleStateIfInURL(new URLSearchParams(document.location.search)).then(async (statusResult) => {
      const resultElement = document.querySelector("#result");
      switch (statusResult.status) {
        case "completed": {
          console.log("Authentication just completed");
          const preLoginUrl = localStorage.getItem("app_preLoginURL");
          localStorage.removeItem("app_preLoginURL");
          if (preLoginUrl) {
            document.location = preLoginUrl;
            return;
          }
          break;
        }
        case "invalid":
        case "error": {
          resultElement.innerText = statusResult.msg;
          return;
        }
      }

      const activeToken = await client.getActiveToken();
      if (!activeToken) {
        result.innerText = "Please log in";
        return;
      }
      const parsed = client.parseJwtPayload(activeToken);
      const parsedIdToken = client.parseJwtPayload(client.getActiveIdToken());
      resultElement.innerHTML = `
      Access token: ${JSON.stringify(parsed, null, 2)}
      ID token: ${JSON.stringify(parsedIdToken, null, 2)}
      `;
      console.log("Access Token:", activeToken);

      if (envs[envName].wellKnown.userinfo_endpoint) {
        const userInfo = await client.retrieveUserInfo(activeToken);
        console.log("USer info", userInfo);
      }
    });
  }
} catch (error) {
  document.querySelector("#result").innerText = error;
}

// Initiate the login process when the user clicks the login button
document.querySelector("#login").addEventListener("click", async () => {
  localStorage.clear();
  localStorage.setItem("env", envName);
  localStorage.setItem("app_preLoginURL", document.location.href);
  try {
    const loginURL = await client.createAuthorizeAndUpdateLocalStorage();
    document.location = loginURL;
  } catch (error) {
    console.error("Error:", error);
  }
});

// Initiate the login process when the user clicks the login button
document.querySelector("#logout").addEventListener("click", async () => {
  localStorage.setItem("app_preLogoutURL", document.location.href);
  try {
    client.logout(document);
  } catch (error) {
    console.error("Error:", error);
  }
});

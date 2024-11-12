import CodeOIDCClient from "./lib/index.js";

// These are test envs
const envs = {
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
      accessType: "offline",
      pkce: false,
      debug: true,
    },
  },
};

/**
 * For this demo we support connecting to integration and production Keycloaks.
 * In a real application you can directly instantiate the client with the correct configuration.
 * @param {string} env
 * @return {CodeOICClient}
 */
function createClient(env) {
  const envConfig = envs.google;
  const client = new CodeOIDCClient(envConfig.options, envConfig.wellKnown);

  return client;
}

const env = localStorage.getItem("env") || "staging";
let client = createClient(env);
window.client = client;
console.log("For the demo, access the client from window.client");
document.querySelector("#env").addEventListener("change", (evt) => {
  const env = evt.target.selectedOptions[0].value;
  localStorage.setItem("env", env);
  client = createClient(env);
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
      resultElement.innerHTML = JSON.stringify(parsed, null, 2);
      console.log("Access Token:", activeToken);
    });
  }
} catch (error) {
  document.querySelector("#result").innerText = error;
}

// Initiate the login process when the user clicks the login button
document.querySelector("#login").addEventListener("click", async () => {
  localStorage.clear();
  localStorage.setItem("app_preLoginURL", document.location.href);
  try {
    const loginURL = await client.createAuthorizeAndUpdateLocalStorage(["openid"]);
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

import CodeOIDCClient from "./lib/index.js";

/**
 * For this demo we support connecting to integration and production Keycloaks.
 * In a real application you can directly instantiate the client with the correct configuration.
 * @param {string} env
 * @return {CodeOICClient}
 */
function createClient(env) {
  const mainURL =
    env === "prod"
      ? "https://keycloak.schweizmobilplus.k8s.fastforward.ch/realms/smobil"
      : "https://keycloak.qa.fastforward.ch/realms/smobil-staging";

  const wellKnown = {
    authorization_endpoint: `${mainURL}/protocol/openid-connect/auth`,
    token_endpoint: `${mainURL}/protocol/openid-connect/token`,
  };

  const client = new CodeOIDCClient(
    {
      // This is the URI that keycloak will use to finish the authentication process
      // It must be an exact URL, not a prefix.
      redirectUri: "http://localhost:8000/",
      // The client ID is provided by your SSO server
      clientId: "schweizmobil-website",
      // PKCE is an optional security feature, that must be enabled in your SSO server.
      pkce: true,
    },
    // You can create the well-known configuration yourself or retrieve it from your SSO server.
    wellKnown,
  );

  return client;
}

const env = localStorage.getItem("env") || "staging";
let client = createClient(env);
document.querySelector("#env").addEventListener("change", (evt) => {
  const env = evt.target.selectedOptions[0].value;
  localStorage.setItem("env", env);
  client = createClient(env);
});

try {
  // When the demo starts, try to finish the login process
  await client.handleStateIfInURL(new URLSearchParams(document.location.search)).then(async (status) => {
    const resultElement = document.querySelector("#result");
    switch (status) {
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
        resultElement.innerText = status.msg;
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
} catch (error) {
  document.querySelector("#result").innerText = error;
}

// Initiate the login process when the user clicks the login button
document.querySelector("#login").addEventListener("click", async () => {
  localStorage.clear();
  localStorage.setItem("app_preLoginURL", document.location.href);
  try {
    const loginURL = await client.createAuthorizeAndUpdateLocalStorage(["openid", "roles"]);
    document.location = loginURL;
  } catch (error) {
    console.error("Error:", error);
  }
});

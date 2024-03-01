import CodeOIDCClient from "./lib/index.js";

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
      redirectUri: "http://localhost:8000/",
      clientId: "schweizmobil-website",
      pkce: true,
      checkToken: async (token) => {
        return true;
      },
    },
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
  await client.handleStateIfInURL(new URLSearchParams(document.location.search)).then(async () => {
    console.log("Authentication completed");
    const newAT = await client.getActiveToken();
    if (!newAT) {
      document.querySelector("#result").innerText = "Please log in";
      return;
    }
    const parsed = client.parseJwtPayload(newAT);
    document.querySelector("#result").innerHTML = JSON.stringify(parsed, null, 2);
    console.log("Access Token:", newAT, newAT);
    const preLoginUrl = localStorage.getItem("app_preLoginURL");
    localStorage.removeItem("app_preLoginURL");
    if (preLoginUrl) {
      document.location = preLoginUrl;
    }
  });
} catch (error) {
  document.querySelector("#result").innerText = error;
}

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

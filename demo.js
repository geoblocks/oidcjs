import { CodeOICClient } from "./lib/index.js";

const mainURL = "https://keycloak.qa.fastforward.ch/realms/smobil-staging";
const wellKnown = {
  authorization_endpoint: `${mainURL}/protocol/openid-connect/auth`,
  token_endpoint: `${mainURL}/protocol/openid-connect/token`,
};

const client = new CodeOICClient(
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

client.handleStateIfInURL(new URLSearchParams(document.location.search)).then(async () => {
  console.log("Authentication completed");
  const newAT = await client.getActiveToken();
  console.log("Access Token:", newAT, client.parseJwtPayload(newAT));
});

document.querySelector("#login").addEventListener("click", async () => {
  try {
    const loginURL = await client.createAuthorizeAndUpdateLocalStorage();
    document.location = loginURL;
  } catch (error) {
    console.error("Error:", error);
  }
});

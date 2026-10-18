"use strict";

// No inline handlers: the CSP in SecurityHeadersFilter allows only script-src 'self'.
const output = document.getElementById("output");

function show(value) {
  output.textContent = typeof value === "string" ? value : JSON.stringify(value, null, 2);
}

async function call(path, options) {
  const response = await fetch(path, options);
  const text = await response.text();
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (notJson) {
    parsed = text;
  }
  show({ status: response.status, body: parsed });
  return response;
}

document.getElementById("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const body = new URLSearchParams({
    username: document.getElementById("username").value,
    password: document.getElementById("password").value,
  });
  // Same-origin request, so the cookie the response sets is stored by the browser and replayed on
  // the next call automatically. credentials: "include" matters only if the API is ever moved to
  // another origin, where it must be paired with a CORS allowlist that names this origin exactly.
  await call("api/login", { method: "POST", body: body, credentials: "include" });
});

document.getElementById("whoami").addEventListener("click", () => {
  call("api/whoami", { method: "GET", credentials: "include" });
});

document.getElementById("logout").addEventListener("click", () => {
  call("api/logout", { method: "POST", credentials: "include" });
});

show("idle - POST credentials to api/login");

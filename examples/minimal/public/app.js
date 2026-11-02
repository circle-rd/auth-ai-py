const MICRO_PER_EUR = 1_000_000n;
const WALLET_POLL_MS = 15_000;

function element(id) {
  const found = document.getElementById(id);
  if (!found) throw new Error(`Missing #${id}`);
  return found;
}

const show = (id, value) => {
  element(id).textContent =
    typeof value === "string" ? value : JSON.stringify(value, null, 2);
};

/** Exact decimal euros of a micro-euro amount, truncated like the SDK's `format_euros`. */
function formatEuros(microEuros, fractionDigits = 2) {
  const amount = BigInt(microEuros);
  const absolute = amount < 0n ? -amount : amount;
  let text = String(absolute / MICRO_PER_EUR);
  if (fractionDigits > 0) {
    const micro = String(absolute % MICRO_PER_EUR).padStart(6, "0");
    text += `.${micro.slice(0, fractionDigits)}`;
  }
  return amount < 0n && /[1-9]/.test(text) ? `-${text}` : text;
}

/** A feature is enabled when present and neither `false` nor `0` nor `""`. */
function hasFeature(user, key) {
  const value = user.features?.[key];
  return value !== undefined && value !== null && ![false, 0, ""].includes(value);
}

/** Same-origin JSON call to the backend; the session cookie is the only credential. */
async function send(path, { body, method, headers } = {}) {
  const response = await fetch(path, {
    method: method ?? (body === undefined ? "GET" : "POST"),
    headers: {
      accept: "application/json",
      ...(body === undefined ? {} : { "content-type": "application/json" }),
      ...headers,
    },
    credentials: "same-origin",
    redirect: "error",
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const data = await response.json().catch(() => undefined);
  return { status: response.status, ok: response.ok, data };
}

/** The /api routes: errors come back as data to display, not as exceptions. */
async function api(path, body) {
  const { ok, status, data } = await send(path, { body });
  return ok ? data : { status, ...data };
}

/** The sign-in routes of the SDK under /auth; failures throw `{ code, message }`. */
async function authCall(path, options) {
  const { ok, status, data } = await send(`/auth${path}`, options);
  if (!ok) {
    const { code = "API_001", message = `The server answered ${status}` } =
      data?.error ?? {};
    throw Object.assign(new Error(message), { code });
  }
  return data;
}

async function getUser() {
  const { status, ok, data } = await send("/auth/me");
  if (status === 401) return null;
  if (!ok) throw new Error(data?.error?.message ?? `The server answered ${status}`);
  return data.user;
}

const login = (next) =>
  location.assign(`/auth/login?next=${encodeURIComponent(next)}`);

async function logout() {
  const { logoutUrl } = await authCall("/logout", { method: "POST" });
  location.assign(logoutUrl ?? "/");
}

// ── Wallet ──

let walletTicket = 0;
let walletTimer;

async function refreshWallet() {
  // A slow answer must not overwrite a newer one.
  const ticket = (walletTicket += 1);
  try {
    const [wallet, stats] = await Promise.all([
      authCall("/wallet"),
      authCall("/wallet/stats?days=7"),
    ]);
    if (ticket !== walletTicket) return;
    show(
      "wallet",
      `${formatEuros(wallet.balance, 4)} € · canSpend=${wallet.canSpend}` +
        ` · spent 7d ${formatEuros(stats.total, 4)} € in ${stats.calls} calls`,
    );
    element("topup").href = wallet.topupUrl;
  } catch (err) {
    if (ticket === walletTicket) show("wallet", `error: ${err.code} ${err.message}`);
  }
}

function startWallet() {
  void refreshWallet();
  walletTimer ??= setInterval(() => void refreshWallet(), WALLET_POLL_MS);
}

// ── Session ──

let state = { status: "loading", user: null, error: null };
let started = false;

function render() {
  const { status, user, error } = state;
  const bar = element("session");
  bar.replaceChildren();
  element("app").hidden = status !== "authenticated";
  if (status === "authenticated" && user) {
    const out = document.createElement("button");
    out.textContent = `Sign out ${user.name ?? user.email ?? user.sub}`;
    out.addEventListener("click", () => void logout());
    bar.append(out);
    show("user", { ...user, canUseBeta: hasFeature(user, "beta") });
  } else {
    const inButton = document.createElement("button");
    inButton.textContent =
      status === "loading" ? "Loading…" : error ? "Retry sign in" : "Sign in";
    inButton.addEventListener("click", () => login("/"));
    bar.append(inButton);
    if (error) bar.append(` ${error.code}: ${error.message}`);
  }
}

async function refreshSession() {
  try {
    const user = await getUser();
    state = user
      ? { status: "authenticated", user, error: null }
      : { status: "unauthenticated", user: null, error: null };
  } catch (err) {
    // Keep the last known user: a failed refresh does not sign anyone out.
    state = {
      status: "error",
      user: state.user,
      error: { code: err.code ?? "API_001", message: err.message },
    };
  }
  render();
  if (state.status === "authenticated" && !started) {
    started = true;
    startWallet();
    void load();
  }
}

async function load() {
  show("gateway", await api("/api/gateway"));
  const select = element("chat-model");
  try {
    for (const model of (await authCall("/models")).models) {
      select.add(new Option(model.id, model.id));
    }
  } catch (err) {
    show("chat-out", `models: ${err.code} ${err.message}`);
  }
}

// ── Actions ──

element("chat").addEventListener("submit", (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  show("chat-out", "…");
  void api("/api/chat", {
    model: form.get("model"),
    message: form.get("message"),
  }).then((answer) => {
    show("chat-out", answer);
    void refreshWallet();
  });
});

element("embed").addEventListener("click", () => {
  const model = element("chat-model");
  const embedding = [...model.options].find((o) => /embed/i.test(o.value));
  show("embed-out", "…");
  void api("/api/embed", {
    model: embedding?.value ?? "perplexity/pplx-embed-v1-0.6b",
    input: "The quick brown fox",
  }).then((answer) => {
    show("embed-out", answer);
    setTimeout(() => void refreshWallet(), 6_000);
  });
});

element("consume").addEventListener("click", () => {
  void api("/api/consume", { key: "test.calls", value: 1 }).then((answer) =>
    show("consume-out", answer),
  );
});

element("selftest").addEventListener("click", () => {
  show("selftest-out", "Running (up to a minute)…");
  void api("/api/selftest", {}).then((answer) => {
    show("selftest-out", answer);
    void refreshWallet();
  });
});

render();
void refreshSession();

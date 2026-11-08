"use strict";

const $ = (id) => document.getElementById(id);
const state = { credentials: [], credential: null, cooldown: 0 };

// ---------------------------------------------------------------- wire log
function addLog(entries = []) {
  const ol = $("log");
  if (entries.length && ol.querySelector(".empty")) ol.innerHTML = "";
  for (const e of entries) {
    const li = document.createElement("li");
    const ok = e.status >= 200 && e.status < 300;
    li.innerHTML = `<details class="entry ${ok ? "" : "bad"}">
      <summary><span class="st">${e.status || "ERR"}</span><span class="meth">${esc(e.http || "POST /csc/v2/" + e.method)}</span>
      <span class="ms">${e.ms} ms</span><span class="lbl">${esc(e.step || "")}</span></summary>
      <pre>${e.auth ? `<span class="k">Authorization:</span> ${esc(e.auth)}\n` : ""}<span class="k">Request</span>
${esc(JSON.stringify(e.request, null, 2))}

<span class="k">Response ${e.status}</span>
${e.response === null ? "(no content)" : esc(JSON.stringify(e.response, null, 2))}</pre></details>`;
    ol.prepend(li);
  }
}
$("clearLog").onclick = () => { $("log").innerHTML = '<li class="empty">Log cleared.</li>'; };

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

// ---------------------------------------------------------------- helpers
async function api(path, options = {}) {
  const res = await fetch(path, { credentials: "same-origin", ...options });
  let data = {};
  try { data = await res.json(); } catch { /* empty body */ }
  addLog(data.log);
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}
const postJSON = (path, body) => api(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });

function setStep(n) {
  for (let i = 1; i <= 5; i++) {
    const el = $("s" + i);
    el.dataset.state = i < n ? "complete" : i === n ? "active" : "locked";
  }
  const active = $("s" + n);
  const focusable = active.querySelector("input:not([type=file]), button");
  active.scrollIntoView({ behavior: "smooth", block: "nearest" });
  if (focusable && n !== 2) setTimeout(() => focusable.focus(), 250);
}

async function busy(button, errEl, fn) {
  errEl.textContent = "";
  const label = button.textContent;
  button.disabled = true;
  button.textContent = "Working…";
  try { await fn(); }
  catch (err) { errEl.textContent = err.message; }
  finally { button.disabled = false; button.textContent = label; }
}

const kb = (n) => (n / 1024).toFixed(1) + " KB";
const genTime = (t) => t ? `${t.slice(0, 4)}-${t.slice(4, 6)}-${t.slice(6, 8)}` : "";

function showNotice(n) {
  const el = $("notice");
  if (!n) { el.hidden = true; return; }
  el.className = "notice " + (n.kind || "ok");
  el.textContent = n.text;
  el.hidden = false;
}

// ---------------------------------------------------------------- step 1: connect
const signupHref = () => { try { return new URL("/account/signup", $("server").value).href; } catch { return "#"; } };
$("server").oninput = () => { $("signupLink").href = signupHref(); };

function showConnected(data) {
  state.credentials = data.credentials;
  $("conn").classList.add("on");
  $("connText").textContent = `${data.service.name} · CSC ${data.service.specs}`;
  $("sum1").innerHTML = `<span>Connected to <b>${esc(data.service.name)}</b></span><span>spec <b>${esc(data.service.specs)}</b></span>
    <span>as <b>${esc(data.username)}</b></span><span>${data.credentials.length} credential(s)</span>`;
  $("newcred").hidden = !data.canCreate;
  renderCreds();
  setStep(2);
}

$("connectForm").onsubmit = (ev) => {
  ev.preventDefault();
  const btn = ev.submitter || ev.target.querySelector("button");
  showNotice(null);
  busy(btn, $("e1"), async () => {
    showConnected(await postJSON("/api/connect", {
      server: $("server").value, username: $("username").value, password: $("password").value,
    }));
  });
};

// after the round trip through the provider's consent page
(async () => {
  try {
    const data = await api("/api/state");
    if (data.connected) showConnected(data);
    showNotice(data.notice);
  } catch { /* fresh start */ }
})();

// ---------------------------------------------------------------- step 2: credential
function renderCreds() {
  $("creds").innerHTML = state.credentials.length ? "" : '<p class="hint">No credentials yet. Request one below.</p>';
  for (const c of state.credentials) {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "cred";
    b.innerHTML = `<span class="t">${esc(c.description || c.id)}</span>
      <span class="badge ${c.scal === "2" ? "scal2" : ""}">SCAL ${esc(c.scal)}</span>
      <span class="m">Unlock with <b>${esc(c.expression)}</b> · up to ${c.multisign} signature(s) per approval</span>
      <span class="m mono">${esc(c.subject)} · valid to ${genTime(c.validTo)}</span>`;
    b.onclick = () => chooseCredential(c);
    $("creds").appendChild(b);
  }
}

$("requestCred").onclick = () => {
  const policy = document.querySelector('input[name="policy"]:checked').value;
  busy($("requestCred"), $("e2"), async () => {
    const d = await postJSON("/api/credentials/request", { policy });
    window.location.assign(d.redirect);  // to the provider's oauth2/authorize page
  });
};

function chooseCredential(c) {
  state.credential = c;
  $("sum2").innerHTML = `<span><b>${esc(c.description)}</b></span><span class="badge ${c.scal === "2" ? "scal2" : ""}">SCAL ${esc(c.scal)}</span>
    <span>${esc(c.expression)}</span><button type="button" class="link" id="changeCred">Change</button>`;
  $("changeCred").onclick = () => { $("sum2").innerHTML = ""; setStep(2); };
  $("codeBox").classList.toggle("hidden", !c.needsCode);
  $("codeField").style.display = c.needsCode ? "" : "none";
  $("code").required = c.needsCode;
  $("codeHint").textContent = c.codeHint ? c.codeHint.replace(/^Request a code with credentials\/getChallenge, then enter/, "Enter") : "";
  setStep(3);
}

// ---------------------------------------------------------------- step 3: document
async function upload(file) {
  $("e3").textContent = "";
  if (!file) return;
  if (file.type && file.type !== "application/pdf") { $("e3").textContent = "Please choose a PDF file."; return; }
  const fd = new FormData();
  fd.append("file", file);
  fd.append("credentialID", state.credential.id);
  try {
    const d = await api("/api/document", { method: "POST", body: fd });
    $("sum3").innerHTML = `<span><b>${esc(d.filename)}</b> · ${kb(d.size)}</span>
      <span>Hash to sign (SHA-256 of the PAdES signed attributes):</span><span class="mono">${esc(d.hash)}</span>`;
    resetAuth();
    setStep(4);
  } catch (err) { $("e3").textContent = err.message; }
}
$("file").onchange = (ev) => upload(ev.target.files[0]);
const drop = $("drop");
["dragenter", "dragover"].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.add("over"); }));
["dragleave", "drop"].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.remove("over"); }));
drop.addEventListener("drop", (e) => upload(e.dataTransfer.files[0]));
$("sample").onclick = async () => {
  const blob = await (await fetch("/static/sample-contract.pdf")).blob();
  upload(new File([blob], "sample-contract.pdf", { type: "application/pdf" }));
};

// ---------------------------------------------------------------- step 4: approve
function resetAuth() {
  $("pin").value = ""; $("code").value = ""; $("e4").textContent = "";
}

$("sendCode").onclick = () => {
  const btn = $("sendCode");
  busy(btn, $("e4"), async () => {
    await postJSON("/api/challenge", {});
    $("codeHint").textContent = "Code sent. Check your inbox (and spam folder). It expires in 5 minutes.";
    startCooldown(30);
    $("code").focus();
  });
};

function startCooldown(seconds) {
  const btn = $("sendCode");
  state.cooldown = seconds;
  const tick = () => {
    if (state.cooldown <= 0) { btn.disabled = false; btn.textContent = "Resend code"; return; }
    btn.disabled = true; btn.textContent = `Resend in ${state.cooldown}s`;
    state.cooldown -= 1; setTimeout(tick, 1000);
  };
  setTimeout(tick, 0);
}

$("signForm").onsubmit = (ev) => {
  ev.preventDefault();
  const code = $("code").value.trim();
  if (state.credential.needsCode && !/^\d{6}$/.test(code)) { $("e4").textContent = "Enter the 6-digit code from the email."; return; }
  busy($("signBtn"), $("e4"), async () => {
    const d = await postJSON("/api/sign", { pin: $("pin").value, code });
    const v = d.validation;
    const badge = (ok, label) => `<span class="badge ${ok ? "ok" : "err"}">${ok ? "✓" : "✗"} ${label}</span>`;
    $("result").innerHTML = `<div class="checks">${badge(v.intact, "intact")}${badge(v.valid, "cryptographically valid")}${badge(v.trusted, "chains to trust root")}</div>
      <div class="row">Signer: <b>${esc(v.signer)}</b></div>
      <div class="row">Signing time: <b>${esc(v.signingTime || "n/a")}</b> · ${kb(d.size)}</div>
      <div class="row">Trust root: ${esc(v.trustRoot)} (demo CA, so PDF readers will show "untrusted")</div>`;
    resetAuth();
    setStep(5);
  });
};

// ---------------------------------------------------------------- step 5
$("again").onclick = () => { $("sum3").innerHTML = ""; $("file").value = ""; setStep(3); };

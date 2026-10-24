/* s3pe admin — a small single-page console. No framework, no CDN. */
(() => {
  "use strict";
  const BASE = document.body.dataset.base || "";
  const API = BASE + "/api";
  const $ = (sel, root = document) => root.querySelector(sel);
  const view = $("#view");
  let me = null;

  // ---------- helpers
  async function api(path, body, method) {
    const opts = { method: method || (body === undefined ? "GET" : "POST"), headers: { "X-Requested-With": "s3pe-admin" }, credentials: "same-origin" };
    if (body !== undefined) { opts.headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(body); }
    const r = await fetch(API + path, opts);
    if (opts.method !== "GET" && r.ok) invalidate("/buckets", "/keys", "/audit", "/admins", "/passkeys");
    let data = null;
    try { data = await r.json(); } catch (_) { /* empty body */ }
    if (!r.ok) throw new Error((data && data.error) || `HTTP ${r.status}`);
    return data;
  }
  // Cache of GET results by path: a view renders the last known data at once
  // and re-renders when the fresh answer differs. Mutations clear it.
  const cache = new Map();
  async function cached(path, render) {
    if (cache.has(path)) { try { render(cache.get(path), true); } catch (_) { /* stale render failed; the fresh one follows */ } }
    const fresh = await api(path);
    const json = JSON.stringify(fresh);
    if (!cache.has(path) || JSON.stringify(cache.get(path)) !== json) { cache.set(path, fresh); render(fresh, false); }
    return fresh;
  }
  function invalidate(...prefixes) { for (const k of [...cache.keys()]) if (prefixes.some((p) => k.startsWith(p))) cache.delete(k); }
  function toast(msg, err) {
    const t = $("#toast"); t.textContent = msg; t.className = "toast" + (err ? " err" : ""); t.hidden = false;
    clearTimeout(toast.timer); toast.timer = setTimeout(() => { t.hidden = true; }, err ? 6000 : 3000);
  }
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const fmtBytes = (n) => { const u = ["B", "kB", "MB", "GB", "TB"]; let i = 0, v = Number(n || 0); while (v >= 1000 && i < u.length - 1) { v /= 1000; i++; } return i ? `${v.toFixed(1)} ${u[i]}` : `${v} B`; };
  const fmtDate = (s) => { if (!s) return ""; const d = new Date(s); return isNaN(d) ? esc(s) : `<span class="date">${d.toLocaleDateString(undefined, { year: "numeric", month: "2-digit", day: "2-digit" })} <span class="muted">${d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })}</span></span>`; };
  const perms = (p) => (p.owner ? `<span class="perm rw">owner</span>` : "") + (p.write ? `<span class="perm rw">write</span>` : "") + (p.read ? `<span class="perm">read</span>` : "");
  const ICONS = {
    eye: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></svg>',
    rotate: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M21 12a9 9 0 1 1-3-6.7"/><path d="M21 3v6h-6"/></svg>',
    trash: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 6h18"/><path d="M8 6V4h8v2"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6M14 11v6"/></svg>',
    unlink: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M9 15l6-6"/><path d="M11 6l1.5-1.5a4 4 0 0 1 5.7 5.7L17 11"/><path d="M13 18l-1.5 1.5a4 4 0 0 1-5.7-5.7L7 13"/><path d="M4 4l16 16"/></svg>',
    userOff: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="10" cy="8" r="4"/><path d="M2 21a8 8 0 0 1 13-6"/><path d="M17 15l5 5M22 15l-5 5"/></svg>',
    userOn: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="10" cy="8" r="4"/><path d="M2 21a8 8 0 0 1 13-6"/><path d="M16 18l2 2 4-4"/></svg>',
  };
  const iconBtn = (name, tip, attrs, danger) => `<button class="btn icon${danger ? " danger-icon" : ""}" data-tip="${esc(tip)}" aria-label="${esc(tip)}" ${attrs}>${ICONS[name]}</button>`;

  function render(id) { view.innerHTML = ""; view.appendChild($(id).content.cloneNode(true)); }
  function form(f) { const o = {}; new FormData(f).forEach((v, k) => { o[k] = v; }); f.querySelectorAll("input[type=checkbox]").forEach((c) => { o[c.name] = c.checked; }); return o; }
  async function busy(btn, fn) { if (!btn) return fn(); btn.disabled = true; try { return await fn(); } finally { btn.disabled = false; } }

  // ---------- WebAuthn plumbing (base64url <-> ArrayBuffer)
  const b64u = {
    dec: (s) => { s = s.replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "="; return Uint8Array.from(atob(s), (c) => c.charCodeAt(0)).buffer; },
    enc: (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""),
  };
  function creationOptions(o) {
    const pk = o.publicKey;
    return { ...pk, challenge: b64u.dec(pk.challenge), user: { ...pk.user, id: b64u.dec(pk.user.id) }, excludeCredentials: (pk.excludeCredentials || []).map((c) => ({ ...c, id: b64u.dec(c.id) })) };
  }
  function requestOptions(o) {
    const pk = o.publicKey;
    return { ...pk, challenge: b64u.dec(pk.challenge), allowCredentials: (pk.allowCredentials || []).map((c) => ({ ...c, id: b64u.dec(c.id) })) };
  }
  function regCredential(c) {
    return { id: c.id, rawId: b64u.enc(c.rawId), type: c.type, extensions: c.getClientExtensionResults ? c.getClientExtensionResults() : {},
      response: { attestationObject: b64u.enc(c.response.attestationObject), clientDataJSON: b64u.enc(c.response.clientDataJSON) } };
  }
  function authCredential(c) {
    return { id: c.id, rawId: b64u.enc(c.rawId), type: c.type, extensions: c.getClientExtensionResults ? c.getClientExtensionResults() : {},
      response: { authenticatorData: b64u.enc(c.response.authenticatorData), clientDataJSON: b64u.enc(c.response.clientDataJSON), signature: b64u.enc(c.response.signature), userHandle: c.response.userHandle ? b64u.enc(c.response.userHandle) : null } };
  }
  async function registerPasskey(begin, finishPath, passkeyName) {
    if (!window.PublicKeyCredential) throw new Error("this browser has no passkey support");
    const cred = await navigator.credentials.create({ publicKey: creationOptions(begin.options) });
    return api(finishPath, { challenge_id: begin.challenge_id, credential: regCredential(cred), passkey_name: passkeyName || "" });
  }

  const details = (d) => { if (!d || typeof d !== "object") return ""; const parts = Object.entries(d).filter(([, v]) => v !== null && v !== "" && !(Array.isArray(v) && !v.length)).map(([k, v]) => `<span><b>${esc(k)}</b>: ${esc(typeof v === "object" ? JSON.stringify(v) : v)}</span>`); return parts.length ? `<div class="details">${parts.join("")}</div>` : '<span class="muted">—</span>'; };
  const ago = (s) => { const d = new Date(s); if (isNaN(d)) return ""; const m = Math.round((Date.now() - d) / 60000); if (m < 1) return "just now"; if (m < 60) return `${m} min ago`; const h = Math.round(m / 60); if (h < 48) return `${h} h ago`; return `${Math.round(h / 24)} d ago`; };
  const ACTION_LABEL = { "bucket.created": "created bucket", "bucket.deleted": "deleted bucket", "key.created": "created key", "key.deleted": "deleted key", "key.rotated": "rotated key", "key.secret_revealed": "revealed the secret of", "bucket.key.allowed": "gave access on", "bucket.key.denied": "removed access on", "login": "signed in", "admin.joined": "joined as administrator", "admin.invited": "invited", "admin.disabled": "disabled", "admin.enabled": "enabled", "passkey.added": "added passkey", "passkey.removed": "removed passkey" };

  async function showOverview() {
    render("#t-overview");
    const kpi = (label, value, hint, tone) => `<div class="kpi ${tone || ""}"><div class="label">${esc(label)}</div><div class="value">${value}</div>${hint ? `<div class="hint">${hint}</div>` : ""}</div>`;
    api("/health").then((h) => { const p = $("#o-health"); p.textContent = `Garage ${h.status} · ${h.connectedNodes}/${h.knownNodes} nodes · ${h.partitionsAllOk}/${h.partitions} partitions ok`; p.className = "pill " + (h.status === "healthy" ? "ok" : "bad"); }).catch((x) => { const p = $("#o-health"); p.textContent = "Garage unreachable"; p.className = "pill bad"; });
    let buckets = [], keys = [], admins = { admins: [], invites: [] }, audit = [];
    const paint = () => {
      const objects = buckets.reduce((a, b) => a + (b.objects || 0), 0);
      const bytes = buckets.reduce((a, b) => a + (b.bytes || 0), 0);
      const mpu = buckets.reduce((a, b) => a + (b.unfinishedMultipartUploads || 0), 0);
      const noKey = buckets.filter((b) => !(b.keys || []).length);
      const orphanKeys = keys.filter((k) => !(k.buckets || []).length);
      const rw = keys.filter((k) => (k.buckets || []).some((b) => b.permissions && b.permissions.write)).length;
      const active = admins.admins.filter((a) => !a.disabled).length;
      const pending = admins.invites.filter((i) => !i.used_at && new Date(i.expires_at) > new Date()).length;
      const logins7 = audit.filter((e) => e.action === "login" && Date.now() - new Date(e.ts) < 7 * 86400000).length;
      $("#o-kpis").innerHTML =
        kpi("Buckets", buckets.length, noKey.length ? `${noKey.length} without any key` : "all reachable by a key") +
        kpi("Objects", objects.toLocaleString(), `${fmtBytes(bytes)} stored`, "teal") +
        kpi("Keys", keys.length, `${rw} can write · ${keys.length - rw} read only`, "navy") +
        kpi("Administrators", active, pending ? `${pending} invitation${pending > 1 ? "s" : ""} pending` : `${logins7} sign-in${logins7 === 1 ? "" : "s"} this week`, "amber") +
        kpi("Unfinished uploads", mpu, mpu ? "multipart uploads never completed" : "nothing hanging", mpu ? "amber" : "");
      const alerts = [];
      if (orphanKeys.length) alerts.push(`<div class="alert">🔑 ${orphanKeys.length} key${orphanKeys.length > 1 ? "s" : ""} without any bucket: <span class="mono">${orphanKeys.map((k) => esc(k.name)).join(", ")}</span>. <a href="#keys">Review or delete</a>.</div>`);
      if (noKey.length) alerts.push(`<div class="alert">🪣 ${noKey.length} bucket${noKey.length > 1 ? "s" : ""} no key can reach: <span class="mono">${noKey.map((b) => esc((b.globalAliases || [])[0] || b.id.slice(0, 12))).join(", ")}</span>.</div>`);
      const reveals = audit.filter((e) => e.action === "key.secret_revealed" && Date.now() - new Date(e.ts) < 7 * 86400000).length;
      if (reveals) alerts.push(`<div class="alert">👁 ${reveals} secret reveal${reveals > 1 ? "s" : ""} in the last 7 days. <a href="#audit">See who</a>.</div>`);
      $("#o-alerts").innerHTML = alerts.join(""); $("#o-alerts").hidden = !alerts.length;
      const top = [...buckets].sort((a, b) => (b.bytes || 0) - (a.bytes || 0)).slice(0, 6); const max = Math.max(1, ...top.map((b) => b.bytes || 0));
      $("#o-bars").innerHTML = top.length ? top.map((b) => `<div class="bar"><a class="name" href="#bucket/${esc(b.id)}">${esc((b.globalAliases || [])[0] || b.id.slice(0, 12))}</a><div class="track"><div class="fill" style="width:${Math.max(2, Math.round(100 * (b.bytes || 0) / max))}%"></div></div><div class="n">${fmtBytes(b.bytes)} · ${(b.objects || 0).toLocaleString()} obj</div></div>`).join("") : `<p class="muted">No buckets yet.</p>`;
      const feed = audit.filter((e) => e.action !== "login").slice(0, 8);
      $("#o-feed").innerHTML = feed.length ? feed.map((e) => `<div class="ev"><div><b>${esc(ACTION_LABEL[e.action] || e.action)}</b> <span class="mono">${esc(e.target)}</span></div><div class="muted small nowrap">${ago(e.ts)}</div><div class="who">${esc(e.admin)}</div></div>`).join("") : `<p class="muted">Nothing yet.</p>`;
    };
    await Promise.all([
      cached("/buckets", (d) => { buckets = d; paint(); }).catch(() => {}),
      cached("/keys", (d) => { keys = d; paint(); }).catch(() => {}),
      cached("/admins", (d) => { admins = d; paint(); }).catch(() => {}),
      cached("/audit?limit=500", (d) => { audit = d; paint(); }).catch(() => {}),
    ]);
    paint();
  }

  // ---------- views
  async function showLogin(error) {
    $("#nav").hidden = true; render("#t-login");
    const err = $("#login-error"); if (error) { err.textContent = error; err.hidden = false; }
    $("#login-form").addEventListener("submit", async (e) => {
      e.preventDefault(); err.hidden = true;
      await busy(e.submitter, async () => {
        try {
          const begin = await api("/login/begin", { email: form(e.target).email });
          const cred = await navigator.credentials.get({ publicKey: requestOptions(begin.options) });
          const r = await api("/login/finish", { challenge_id: begin.challenge_id, credential: authCredential(cred) });
          me = r.admin; location.hash = "#overview"; start();
        } catch (x) { err.textContent = x.message; err.hidden = false; }
      });
    });
  }
  async function showInvite(token) {
    $("#nav").hidden = true; render("#t-invite");
    const err = $("#invite-error");
    let begin;
    try { begin = await api("/invite/begin", { token }); $("#invite-who").textContent = `${begin.name} <${begin.email}>`; }
    catch (x) { err.textContent = x.message; err.hidden = false; $("#invite-form").hidden = true; return; }
    $("#invite-form").addEventListener("submit", async (e) => {
      e.preventDefault(); err.hidden = true;
      await busy(e.submitter, async () => {
        try {
          const r = await registerPasskey(begin, "/invite/finish", form(e.target).passkey_name);
          me = r.admin; history.replaceState(null, "", location.pathname); location.hash = "#profile"; start();
        } catch (x) {
          err.textContent = x.message + (x.message.includes("expired") ? "" : " — reload the invitation link to try again"); err.hidden = false;
        }
      });
    });
  }

  async function showBuckets() {
    render("#t-buckets");
    const rows = $("#bucket-rows"); rows.innerHTML = `<tr><td colspan="5" class="empty">Loading…</td></tr>`;
    api("/health").then((h) => { const p = $("#health"); p.textContent = `Garage ${h.status} · ${h.connectedNodes}/${h.knownNodes} nodes`; p.className = "pill " + (h.status === "healthy" ? "ok" : "bad"); }).catch(() => {});
    await cached("/buckets", renderBuckets);
    function renderBuckets(buckets) {
    rows.innerHTML = buckets.length ? buckets.map((b) => {
      const name = (b.globalAliases && b.globalAliases[0]) || b.id.slice(0, 12);
      if (b.error) return `<tr><td><a href="#bucket/${esc(b.id)}">${esc(name)}</a></td><td colspan="4" class="error">${esc(b.error)}</td></tr>`;
      return `<tr><td><a href="#bucket/${esc(b.id)}" class="cell-title">${esc(name)}</a><span class="cell-sub">${esc(b.id.slice(0, 16))}…</span></td><td class="num">${b.objects}</td><td class="num">${fmtBytes(b.bytes)}</td><td>${b.keys.length ? `<div class="keylist">${b.keys.map((k) => `<span><span class="mono">${esc(k.name)}</span> ${perms(k.permissions)}</span>`).join("")}</div>` : '<span class="muted">none</span>'}</td><td>${fmtDate(b.created)}</td></tr>`;
    }).join("") : `<tr><td colspan="5" class="empty">No buckets yet.</td></tr>`;
    $("#bucket-count").textContent = buckets.length ? `(${buckets.length})` : "";
    }
    $("#new-bucket").onclick = () => { $("#bucket-form").hidden = false; $("#create-bucket input[name=name]").focus(); };
    $("#cancel-bucket").onclick = () => { $("#bucket-form").hidden = true; };
    $("#create-bucket").addEventListener("submit", async (e) => {
      e.preventDefault();
      await busy(e.submitter, async () => {
        try {
          const r = await api("/buckets", form(e.target));
          toast(`Bucket ${r.bucket.globalAliases[0]} created`);
          if (r.keys && r.keys.length) { showSecrets(r.keys, () => showBuckets()); } else { showBuckets(); }
        } catch (x) { toast(x.message, true); }
      });
    });
  }

  function showSecrets(keys, done, title, note) {
    view.innerHTML = `<h1>${esc(title || "New keys")}</h1>` + (note ? `<p class="muted">${esc(note)}</p>` : "");
    keys.forEach((k) => {
      const t = $("#t-secret").content.cloneNode(true);
      const p = k.permissions || {}; const prof = p.write ? "read and write" : (p.read ? "read only" : "no bucket");
      t.querySelectorAll("[data-f]").forEach((el) => { const f = el.dataset.f; el.textContent = f === "permissions" ? prof : (k[f] || ""); });
      t.querySelector("[data-copy]").onclick = () => { navigator.clipboard.writeText(`# ${k.name} (${prof}) — bucket ${k.bucket}\nAWS_ACCESS_KEY_ID=${k.accessKeyId}\nAWS_SECRET_ACCESS_KEY=${k.secretAccessKey}\n`); toast("Copied"); };
      t.querySelector("[data-done]").onclick = () => done();
      view.appendChild(t);
    });
  }

  async function showBucket(id) {
    render("#t-bucket");
    const b = await api(`/buckets/${encodeURIComponent(id)}`);
    const name = (b.globalAliases && b.globalAliases[0]) || b.id.slice(0, 12);
    $("#b-name").textContent = name; $("#b-id").textContent = b.id;
    $("#b-objects").textContent = b.objects; $("#b-size").textContent = fmtBytes(b.bytes); $("#b-mpu").textContent = b.unfinishedMultipartUploads;
    const rows = $("#b-keys");
    rows.innerHTML = b.keys.length ? b.keys.map((k) => `<tr><td><span class="cell-title">${esc(k.name)}</span><span class="cell-sub">${esc(k.accessKeyId)}</span></td><td>${perms(k.permissions)}</td><td><div class="actions">${iconBtn("unlink", "Remove access", `data-deny="${esc(k.accessKeyId)}"`, true)}</div></td></tr>`).join("") : `<tr><td colspan="3" class="empty">No key has access to this bucket.</td></tr>`;
    rows.querySelectorAll("[data-deny]").forEach((btn) => { btn.onclick = () => busy(btn, async () => { try { await api(`/buckets/${encodeURIComponent(id)}/deny`, { key_id: btn.dataset.deny }); toast("Access removed"); showBucket(id); } catch (x) { toast(x.message, true); } }); });
    $("#b-add-key").onclick = async () => {
      $("#b-key-form").hidden = false;
      const keys = await api("/keys");
      $("#b-key-select").innerHTML = keys.map((k) => `<option value="${esc(k.accessKeyId)}">${esc(k.name)} (${esc(k.accessKeyId)})</option>`).join("") || `<option value="">no keys: create one in Keys</option>`;
    };
    $("#b-cancel-key").onclick = () => { $("#b-key-form").hidden = true; };
    $("#b-allow").addEventListener("submit", async (e) => {
      e.preventDefault();
      await busy(e.submitter, async () => { try { await api(`/buckets/${encodeURIComponent(id)}/allow`, form(e.target)); toast("Access granted"); showBucket(id); } catch (x) { toast(x.message, true); } });
    });
    $("#b-delete").addEventListener("submit", async (e) => {
      e.preventDefault();
      await busy(e.submitter, async () => { try { await api(`/buckets/${encodeURIComponent(id)}/delete`, form(e.target)); toast(`Bucket ${name} deleted`); location.hash = "#buckets"; } catch (x) { toast(x.message, true); } });
    });
  }

  async function showKeys() {
    render("#t-keys");
    const rows = $("#key-rows"); rows.innerHTML = `<tr><td colspan="4" class="empty">Loading…</td></tr>`;
    cached("/buckets", (buckets) => { $("#key-bucket").innerHTML = `<option value="">(none yet)</option>` + buckets.map((b) => `<option value="${esc(b.id)}">${esc((b.globalAliases || [])[0] || b.id.slice(0, 12))}</option>`).join(""); }).catch(() => {});
    await cached("/keys", renderKeys);
    function renderKeys(keys) {
    $("#key-count").textContent = keys.length ? `(${keys.length})` : "";
    rows.innerHTML = keys.length ? keys.map((k) => `<tr><td><span class="cell-title">${esc(k.name)}</span><span class="cell-sub">${esc(k.accessKeyId)}</span></td><td>${(k.buckets || []).length ? `<div class="keylist">${k.buckets.map((b) => `<span><a href="#bucket/${esc(b.id)}">${esc((b.globalAliases || [])[0] || b.id.slice(0, 12))}</a> ${perms(b.permissions)}</span>`).join("")}</div>` : '<span class="muted">no bucket</span>'}</td><td>${fmtDate(k.created)}</td><td><div class="actions">${iconBtn("eye", "Show secret", `data-reveal="${esc(k.accessKeyId)}"`)}${iconBtn("rotate", "Rotate key (new secret)", `data-rotate="${esc(k.accessKeyId)}" data-name="${esc(k.name)}"`)}${iconBtn("trash", "Delete key", `data-del="${esc(k.accessKeyId)}" data-name="${esc(k.name)}"`, true)}</div></td></tr>`).join("") : `<tr><td colspan="4" class="empty">No keys yet.</td></tr>`;
    rows.querySelectorAll("[data-reveal]").forEach((btn) => {
      btn.onclick = () => busy(btn, async () => { try { const k = await api(`/keys/${encodeURIComponent(btn.dataset.reveal)}/secret`); showSecrets([k], () => showKeys(), "Secret of an existing key", "Revealing a secret is recorded in the audit log. Prefer rotating the key if the secret may have leaked."); } catch (x) { toast(x.message, true); } });
    });
    rows.querySelectorAll("[data-rotate]").forEach((btn) => {
      btn.onclick = async () => {
        const typed = prompt(`Rotate key ${btn.dataset.name}? A new secret replaces the old one at once; every program using the old secret stops working until updated. Type the key's name to confirm.`);
        if (typed === null) return;
        await busy(btn, async () => { try { const k = await api(`/keys/${encodeURIComponent(btn.dataset.rotate)}/rotate`, { name: typed }); showSecrets([k], () => showKeys(), "New secret", "The old access key id and secret no longer work."); } catch (x) { toast(x.message, true); } });
      };
    });
    rows.querySelectorAll("[data-del]").forEach((btn) => {
      btn.onclick = async () => {
        const typed = prompt(`Delete key ${btn.dataset.name}? Every program using it stops working. Type its name to confirm.`);
        if (typed === null) return;
        await busy(btn, async () => { try { await api(`/keys/${encodeURIComponent(btn.dataset.del)}/delete`, { name: typed }); toast("Key deleted"); showKeys(); } catch (x) { toast(x.message, true); } });
      };
    });
    }
    $("#new-key").onclick = () => { $("#key-form").hidden = false; $("#create-key input[name=name]").focus(); };
    $("#cancel-key").onclick = () => { $("#key-form").hidden = true; };
    $("#create-key").addEventListener("submit", async (e) => {
      e.preventDefault();
      await busy(e.submitter, async () => {
        try { const k = await api("/keys", form(e.target)); showSecrets([k], () => showKeys()); } catch (x) { toast(x.message, true); }
      });
    });
  }

  async function showAdmins() {
    render("#t-admins");
    await cached("/admins", renderAdmins);
    function renderAdmins(d) {
    $("#admin-count").textContent = d.admins.length ? `(${d.admins.length})` : "";
    $("#admin-rows").innerHTML = d.admins.map((a) => `<tr><td><span class="cell-title">${esc(a.name)}</span></td><td>${esc(a.email)}</td><td>${fmtDate(a.created_at)}</td><td>${a.disabled ? '<span class="pill bad">disabled</span>' : '<span class="pill ok">active</span>'}</td><td><div class="actions">${a.id === me.id ? '<span class="muted small">you</span>' : iconBtn(a.disabled ? "userOn" : "userOff", a.disabled ? "Enable administrator" : "Disable administrator", `data-toggle="${esc(a.id)}" data-disabled="${a.disabled}"`, !a.disabled)}</div></td></tr>`).join("");
    $("#admin-rows").querySelectorAll("[data-toggle]").forEach((btn) => {
      btn.onclick = () => busy(btn, async () => { try { await api(`/admins/${encodeURIComponent(btn.dataset.toggle)}/${btn.dataset.disabled === "true" ? "enable" : "disable"}`, {}); showAdmins(); } catch (x) { toast(x.message, true); } });
    });
    const pending = d.invites.filter((i) => !i.used_at && new Date(i.expires_at) > new Date());
    $("#invite-rows").innerHTML = pending.length ? pending.map((i) => `<tr><td>${esc(i.name)}</td><td>${esc(i.email)}</td><td>${esc(i.created_by)}</td><td>${fmtDate(i.expires_at)}</td></tr>`).join("") : `<tr><td colspan="4" class="empty">None.</td></tr>`;
    }
    $("#new-invite").onclick = () => { $("#invite-form-card").hidden = false; $("#create-invite input[name=name]").focus(); };
    $("#create-invite").addEventListener("submit", async (e) => {
      e.preventDefault();
      await busy(e.submitter, async () => {
        try { const r = await api("/admins/invite", form(e.target)); $("#invite-url").textContent = r.url; $("#invite-result").hidden = false; $("#copy-invite").onclick = () => { navigator.clipboard.writeText(r.url); toast("Copied"); }; } catch (x) { toast(x.message, true); }
      });
    });
  }

  async function showAudit() {
    render("#t-audit");
    await cached("/audit?limit=500", (rows) => {
      $("#audit-count").textContent = rows.length ? `(${rows.length})` : "";
      $("#audit-rows").innerHTML = rows.length ? rows.map((r) => `<tr><td class="nowrap">${fmtDate(r.ts)}</td><td>${esc(r.admin)}</td><td class="nowrap"><span class="pill">${esc(r.action)}</span></td><td class="mono">${esc(r.target)}</td><td>${details(r.details)}</td><td class="mono nowrap">${esc(r.ip)}</td></tr>`).join("") : `<tr><td colspan="6" class="empty">Nothing yet.</td></tr>`;
      $("#audit-export").href = URL.createObjectURL(new Blob([JSON.stringify(rows, null, 2)], { type: "application/json" }));
    });
  }

  async function showProfile() {
    render("#t-profile");
    $("#p-name").textContent = me.name; $("#p-email").textContent = me.email;
    const rows = await api("/passkeys");
    $("#passkey-rows").innerHTML = rows.map((p) => `<tr><td><span class="cell-title">${esc(p.name)}</span></td><td>${fmtDate(p.created_at)}</td><td>${fmtDate(p.last_used_at) || '<span class="muted">never</span>'}</td><td><div class="actions">${rows.length > 1 ? iconBtn("trash", "Remove passkey", `data-del="${p.id}"`, true) : '<span class="muted small">last one</span>'}</div></td></tr>`).join("");
    $("#passkey-rows").querySelectorAll("[data-del]").forEach((btn) => { btn.onclick = () => busy(btn, async () => { try { await api(`/passkeys/${btn.dataset.del}/delete`, {}); showProfile(); } catch (x) { toast(x.message, true); } }); });
    $("#add-passkey").onclick = () => { $("#passkey-form").hidden = false; $("#create-passkey input").focus(); };
    $("#create-passkey").addEventListener("submit", async (e) => {
      e.preventDefault();
      await busy(e.submitter, async () => {
        try { const begin = await api("/passkeys/begin", {}); await registerPasskey(begin, "/passkeys/finish", form(e.target).passkey_name); toast("Passkey registered"); showProfile(); } catch (x) { toast(x.message, true); }
      });
    });
  }

  // ---------- routing
  async function route() {
    const h = location.hash.replace(/^#/, "");
    const m = h.match(/^invite=(.+)$/);
    if (m) return showInvite(m[1]);
    if (!me) return showLogin();
    $("#nav").hidden = false; $("#who").textContent = me.name;
    const current = h || "overview";
    document.querySelectorAll("#nav a[data-view]").forEach((a) => a.classList.toggle("active", current.startsWith(a.dataset.view) || (current.startsWith("bucket/") && a.dataset.view === "buckets")));
    try {
      if (h.startsWith("bucket/")) return await showBucket(h.slice(7));
      if (h === "buckets") return await showBuckets();
      if (h === "" || h === "overview") return await showOverview();
      if (h === "keys") return await showKeys();
      if (h === "admins") return await showAdmins();
      if (h === "audit") return await showAudit();
      if (h === "profile") return await showProfile();
      return await showOverview();
    } catch (x) {
      if (/sign in/i.test(x.message)) { me = null; return showLogin("Your session ended; sign in again."); }
      view.innerHTML = `<div class="card"><p class="error">${esc(x.message)}</p></div>`;
    }
  }
  async function start() {
    try { me = (await api("/me")).admin; } catch (_) { me = null; }
    route();
  }
  window.addEventListener("hashchange", route);
  $("#logout").onclick = async () => { try { await api("/logout", {}); } catch (_) {} cache.clear(); me = null; location.hash = ""; showLogin(); };
  start();
})();

// doorman front-end. No framework, no inline script (strict CSP).
"use strict";

(() => {
  const csrf = () => document.querySelector('meta[name="csrf"]')?.content || "";
  const HOLD_MS = 900;

  // ---- toast -----------------------------------------------------------------------------
  let toastTimer;
  function toast(msg) {
    const el = document.getElementById("toast");
    if (!el) return alert(msg);
    el.textContent = msg;
    el.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { el.hidden = true; }, 5000);
  }

  async function postJSON(url, body) {
    const res = await fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "Accept": "application/json", "X-CSRF-Token": csrf() },
      body: JSON.stringify(body || {}),
    });
    let data = {};
    try { data = await res.json(); } catch (_) { /* empty */ }
    if (!res.ok) {
      if (data.redirect) { location.href = data.redirect; }
      throw new Error(data.detail || `Request failed (${res.status})`);
    }
    return data;
  }

  // ---- live refresh of fragments (door panel every 2s, stats every 15s) ----------------------
  let holding = false;
  function startRefresh(el) {
    const url = el.dataset.refresh;
    const base = parseInt(el.dataset.interval || "5000", 10);
    let timer;
    const tick = async () => {
      const interval = document.hidden ? Math.max(base, 30000) : base;
      if (!holding) {
        try {
          const res = await fetch(url, { credentials: "same-origin", headers: { "Accept": "text/html" } });
          if (res.redirected && new URL(res.url).pathname.startsWith("/login")) { location.href = res.url; return; }
          if (res.ok) {
            const html = await res.text();
            const current = document.getElementById(el.id);
            if (!current) return;
            if (el.id === "door-panel") {
              const tpl = document.createElement("template");
              tpl.innerHTML = html.trim();
              const fresh = tpl.content.firstElementChild;
              if (fresh && fresh.outerHTML !== current.outerHTML) {
                current.replaceWith(fresh);
                el = fresh;
                if (fresh.querySelector(".door-label")) document.title = fresh.querySelector(".door-label").textContent + " · doorman";
              }
            } else if (current.innerHTML !== html) {
              current.innerHTML = html;
            }
          }
        } catch (_) { /* offline: try again next tick */ }
      }
      timer = setTimeout(tick, interval);
    };
    timer = setTimeout(tick, base);
    document.addEventListener("visibilitychange", () => {
      if (!document.hidden) { clearTimeout(timer); tick(); }
    });
  }

  async function refreshPanelNow() {
    const res = await fetch("/status", { credentials: "same-origin" });
    if (!res.ok) return;
    const tpl = document.createElement("template");
    tpl.innerHTML = (await res.text()).trim();
    const cur = document.getElementById("door-panel");
    if (cur && tpl.content.firstElementChild) cur.replaceWith(tpl.content.firstElementChild);
  }

  // ---- door actions: tap for close, press-and-hold for open/crack -----------------------------
  async function doAction(btn) {
    const action = btn.dataset.action;
    btn.disabled = true;
    try {
      await postJSON(`/door/${action}`, { confirmed: btn.hasAttribute("data-hold") });
      if (navigator.vibrate) navigator.vibrate(30);
    } catch (e) {
      toast(e.message);
    } finally {
      btn.disabled = false;
      refreshPanelNow();
    }
  }

  function bindHold(btn) {
    let timer = null;
    const start = (ev) => {
      if (btn.disabled || timer) return;
      if (ev.type === "pointerdown" && ev.button !== 0) return;
      ev.preventDefault();
      holding = true;
      btn.style.setProperty("--hold-ms", HOLD_MS + "ms");
      btn.classList.add("holding");
      timer = setTimeout(() => {
        timer = null;
        btn.classList.remove("holding");
        holding = false;
        doAction(btn);
      }, HOLD_MS);
    };
    const cancel = () => {
      if (!timer) return;
      clearTimeout(timer);
      timer = null;
      holding = false;
      btn.classList.remove("holding");
    };
    btn.addEventListener("pointerdown", start);
    ["pointerup", "pointerleave", "pointercancel"].forEach((t) => btn.addEventListener(t, cancel));
    btn.addEventListener("keydown", (e) => { if ((e.key === " " || e.key === "Enter") && !e.repeat) start(e); });
    btn.addEventListener("keyup", (e) => { if (e.key === " " || e.key === "Enter") cancel(); });
    btn.addEventListener("click", (e) => {
      e.preventDefault();
      if (!timer && e.detail !== 0) toast("Press and hold to confirm.");
    });
    btn.addEventListener("contextmenu", (e) => e.preventDefault());
  }

  document.addEventListener("click", (e) => {
    const btn = e.target.closest("button[data-action]:not([data-hold])");
    if (btn) { e.preventDefault(); doAction(btn); }
  });

  // Hold buttons are re-created on each refresh, so bind through delegation on pointerdown.
  document.addEventListener("pointerdown", (e) => {
    const btn = e.target.closest("button[data-hold]");
    if (btn && !btn.dataset.bound) { btn.dataset.bound = "1"; bindHold(btn); btn.dispatchEvent(new PointerEvent("pointerdown", e)); }
  }, true);
  document.addEventListener("focusin", (e) => {
    const btn = e.target.closest?.("button[data-hold]");
    if (btn && !btn.dataset.bound) { btn.dataset.bound = "1"; bindHold(btn); }
  });

  // ---- passkeys (WebAuthn) -------------------------------------------------------------------
  const b64u = {
    toBuf: (s) => {
      const pad = "=".repeat((4 - (s.length % 4)) % 4);
      const bin = atob((s + pad).replace(/-/g, "+").replace(/_/g, "/"));
      return Uint8Array.from(bin, (c) => c.charCodeAt(0)).buffer;
    },
    fromBuf: (buf) => {
      let s = "";
      new Uint8Array(buf).forEach((b) => { s += String.fromCharCode(b); });
      return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    },
  };

  function creationOptions(o) {
    const pk = o.publicKey;
    return {
      publicKey: {
        ...pk,
        challenge: b64u.toBuf(pk.challenge),
        user: { ...pk.user, id: b64u.toBuf(pk.user.id) },
        excludeCredentials: (pk.excludeCredentials || []).map((c) => ({ ...c, id: b64u.toBuf(c.id) })),
      },
    };
  }

  function requestOptions(o) {
    const pk = o.publicKey;
    return {
      publicKey: {
        ...pk,
        challenge: b64u.toBuf(pk.challenge),
        allowCredentials: (pk.allowCredentials || []).map((c) => ({ ...c, id: b64u.toBuf(c.id) })),
      },
    };
  }

  function registrationJSON(cred) {
    return {
      id: cred.id, rawId: b64u.fromBuf(cred.rawId), type: cred.type,
      response: {
        clientDataJSON: b64u.fromBuf(cred.response.clientDataJSON),
        attestationObject: b64u.fromBuf(cred.response.attestationObject),
        transports: cred.response.getTransports ? cred.response.getTransports() : [],
      },
      clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
    };
  }

  function assertionJSON(cred) {
    return {
      id: cred.id, rawId: b64u.fromBuf(cred.rawId), type: cred.type,
      response: {
        clientDataJSON: b64u.fromBuf(cred.response.clientDataJSON),
        authenticatorData: b64u.fromBuf(cred.response.authenticatorData),
        signature: b64u.fromBuf(cred.response.signature),
        userHandle: cred.response.userHandle ? b64u.fromBuf(cred.response.userHandle) : null,
      },
      clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
    };
  }

  async function passkeyAssert(beginUrl, finishUrl, next) {
    const { handle, options } = await postJSON(beginUrl);
    const cred = await navigator.credentials.get(requestOptions(options));
    const out = await postJSON(finishUrl, { handle, credential: assertionJSON(cred), next });
    location.href = out.redirect || "/";
  }

  function passkeyError(e) {
    if (e && e.name === "NotAllowedError") return toast("Passkey request was cancelled or timed out.");
    toast(e.message || String(e));
  }

  const supported = !!(window.PublicKeyCredential && navigator.credentials);
  document.querySelectorAll("[data-passkey-login],[data-passkey-reauth],[data-passkey-register-wrap]").forEach((el) => { el.hidden = !supported; });
  document.querySelectorAll("[data-no-passkey]").forEach((el) => { el.hidden = supported; });

  document.addEventListener("click", async (e) => {
    const login = e.target.closest("[data-passkey-login]");
    const reauth = e.target.closest("[data-passkey-reauth]");
    const register = e.target.closest("[data-passkey-register]");
    try {
      if (login) {
        login.disabled = true;
        await passkeyAssert("/login/passkey/begin", "/login/passkey/finish", login.dataset.next || "/");
      } else if (reauth) {
        reauth.disabled = true;
        await passkeyAssert("/reauth/passkey/begin", "/reauth/passkey/finish", reauth.dataset.next || "/admin");
      } else if (register) {
        register.disabled = true;
        const name = document.getElementById("passkey-name")?.value || "";
        const { handle, options } = await postJSON("/profile/passkeys/begin");
        const cred = await navigator.credentials.create(creationOptions(options));
        const out = await postJSON("/profile/passkeys/finish", { handle, credential: registrationJSON(cred), name });
        location.href = out.redirect || "/profile";
      }
    } catch (err) {
      passkeyError(err);
    } finally {
      [login, reauth, register].forEach((b) => { if (b) b.disabled = false; });
    }
  });

  // ---- small helpers ----------------------------------------------------------------------
  document.addEventListener("click", async (e) => {
    const copy = e.target.closest("[data-copy]");
    if (copy) {
      try { await navigator.clipboard.writeText(copy.dataset.copy); toast("Copied."); }
      catch (_) { toast("Couldn't copy. Select the text and copy it manually."); }
    }
    const reed = e.target.closest("[data-dev-reed]");
    if (reed) {
      try { await postJSON(`/dev/reed/${reed.dataset.devReed}`); refreshPanelNow(); } catch (err) { toast(err.message); }
    }
  });

  document.addEventListener("submit", (e) => {
    const msg = e.target.dataset?.confirm;
    if (msg && !confirm(msg)) e.preventDefault();
  });

  // Window forms: show only the fields for the chosen kind.
  document.querySelectorAll("[data-window-form]").forEach((form) => {
    const sync = () => {
      const kind = (form.querySelector('input[name="kind"]:checked') || form.querySelector('input[name="kind"]'))?.value || "once";
      form.querySelectorAll("[data-kind-show]").forEach((el) => {
        const show = el.dataset.kindShow.split(" ").includes(kind);
        el.hidden = !show;
        el.querySelectorAll("input").forEach((i) => { i.disabled = !show; });
      });
      const date = form.querySelector('input[name="date"]');
      if (date) date.required = kind === "once";
    };
    form.addEventListener("change", sync);
    sync();
  });

  // Header menu: a <details> drop-down on phones, an always-open inline nav from 640px up.
  // (A closed <details> hides its content whatever the CSS says, so keep it open when wide.)
  const menu = document.querySelector("details.menu");
  if (menu) {
    const wide = window.matchMedia("(min-width: 640px)");
    const sync = () => { menu.open = wide.matches; };
    wide.addEventListener("change", sync);
    sync();
    document.addEventListener("click", (e) => {
      if (!wide.matches && menu.open && !menu.contains(e.target)) menu.open = false;
    });
  }

  document.querySelectorAll("[data-refresh]").forEach(startRefresh);
})();

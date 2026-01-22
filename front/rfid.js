document.addEventListener("DOMContentLoaded", async () => {
  const subtitle = document.getElementById("subtitle");
  const who = document.getElementById("who");
  const timeNow = document.getElementById("timeNow");

  const logoutBtn = document.getElementById("logout");
  const refreshLogsBtn = document.getElementById("refreshLogs");
  const refreshUsersBtn = document.getElementById("refreshUsers");

  const dot = document.getElementById("dot");
  const statusText = document.getElementById("statusText");
  const liveName = document.getElementById("liveName");
  const liveUid = document.getElementById("liveUid");
  const liveDoor = document.getElementById("liveDoor");
  const liveAt = document.getElementById("liveAt");

  const logsTableBody = document.querySelector("#logsTable tbody");
  const usersTableBody = document.querySelector("#usersTable tbody");

  const fullNameInput = document.getElementById("fullName");
  const uidInput = document.getElementById("uid");
  const enabledInput = document.getElementById("enabled");
  const btnEnroll = document.getElementById("btnEnroll");
  const btnClear = document.getElementById("btnClear");
  const toast = document.getElementById("toast");

  function nowStr() {
    return new Date().toLocaleString();
  }

  function setDot(state) {
    if (state === "ok") {
      dot.style.background = "var(--good)";
      dot.style.boxShadow = "0 0 0 6px rgba(40,209,124,.12)";
    } else if (state === "bad") {
      dot.style.background = "var(--bad)";
      dot.style.boxShadow = "0 0 0 6px rgba(255,77,77,.12)";
    } else {
      dot.style.background = "var(--warn)";
      dot.style.boxShadow = "0 0 0 6px rgba(255,204,0,.12)";
    }
  }

  function showToast(kind, msg) {
    toast.hidden = false;
    toast.className = `toast ${kind}`;
    toast.textContent = msg;
    setTimeout(() => { toast.hidden = true; }, 2500);
  }

  // horloge
  timeNow.textContent = nowStr();
  setInterval(() => (timeNow.textContent = nowStr()), 1000);

  // Tabs
  document.querySelectorAll(".tab").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach((b) => b.classList.remove("active"));
      document.querySelectorAll(".panel").forEach((p) => p.classList.remove("show"));
      btn.classList.add("active");
      document.getElementById(`tab-${btn.dataset.tab}`).classList.add("show");
    });
  });

  // Auth
  const token = localStorage.getItem("token");
  if (!token) {
    window.location.replace("/front/index.html");
    return;
  }

  logoutBtn.addEventListener("click", () => {
    localStorage.removeItem("token");
    window.location.href = "/front/index.html";
  });

  async function api(path, options = {}) {
    const res = await fetch(path, {
      ...options,
      headers: {
        ...(options.headers || {}),
        Authorization: `Bearer ${token}`,
        Accept: "application/json",
        "Content-Type": "application/json",
      },
    });
    return res;
  }

  subtitle.textContent = "Vérification du token…";
  try {
    const res = await api("/api/auth/validate", { method: "GET" });
    if (res.status !== 200) {
      localStorage.removeItem("token");
      window.location.replace("/front/index.html");
      return;
    }
    const data = await res.json().catch(() => ({}));
    const user = data?.user?.login || data?.login || "Utilisateur";
    who.textContent = user;
    subtitle.textContent = "Connecté.";
  } catch (e) {
    localStorage.removeItem("token");
    window.location.replace("/front/index.html");
    return;
  }

  // Logs
  function setLastBadgeFromRow(r) {
    // r: { uid, person_name, door, allowed, created_at }
    const allowed = !!r.allowed;
    setDot(allowed ? "ok" : "bad");
    statusText.textContent = allowed ? "Accès autorisé" : "Accès refusé";
    liveName.textContent = r.person_name || "Inconnu";
    liveUid.textContent = r.uid || "—";
    liveDoor.textContent = r.door || "MAIN";
    liveAt.textContent = r.created_at ? new Date(r.created_at).toLocaleString() : "—";
  }

  async function loadLogs() {
    logsTableBody.innerHTML = `<tr><td colspan="5" class="muted">Chargement…</td></tr>`;
    try {
      const res = await api("/api/rfid/logs?limit=30", { method: "GET" });

      if (res.status === 401) {
        localStorage.removeItem("token");
        window.location.replace("/front/index.html");
        return;
      }

      const data = await res.json().catch(() => ({}));
      const rows = data.rows || data.data || [];

      if (!rows.length) {
        logsTableBody.innerHTML = `<tr><td colspan="5" class="muted">Aucun badge pour le moment.</td></tr>`;
        setDot("warn");
        statusText.textContent = "En attente…";
        return;
      }

      setLastBadgeFromRow(rows[0]);

      logsTableBody.innerHTML = rows.map((r) => {
        const ok = !!r.allowed;
        return `
          <tr>
            <td>${r.created_at ? new Date(r.created_at).toLocaleString() : "—"}</td>
            <td>${(r.person_name || "Inconnu")}</td>
            <td class="mono">${(r.uid || "—")}</td>
            <td>${(r.door || "MAIN")}</td>
            <td class="${ok ? "badge-ok" : "badge-no"}">${ok ? "OUI" : "NON"}</td>
          </tr>
        `;
      }).join("");
    } catch (e) {
      logsTableBody.innerHTML = `<tr><td colspan="5" class="muted">Erreur de chargement (API manquante ?).</td></tr>`;
      setDot("warn");
      statusText.textContent = "API RFID pas encore prête";
    }
  }

  refreshLogsBtn.addEventListener("click", loadLogs);

  // Enroll
  btnClear.addEventListener("click", () => {
    fullNameInput.value = "";
    uidInput.value = "";
    enabledInput.checked = true;
  });

  btnEnroll.addEventListener("click", async () => {
    const full_name = fullNameInput.value.trim();
    const uid = uidInput.value.trim();
    const enabled = enabledInput.checked;

    if (!full_name || !uid) {
      showToast("bad", "Nom + UID obligatoires.");
      return;
    }

    try {
      const res = await api("/api/rfid/enroll", {
        method: "POST",
        body: JSON.stringify({ full_name, uid, enabled }),
      });

      const data = await res.json().catch(() => ({}));

      if (res.status === 200 && data.success) {
        showToast("ok", "Carte enregistrée.");
        await loadUsers();
        return;
      }

      if (res.status === 403) {
        showToast("bad", "Refusé : admin requis.");
        return;
      }
      if (res.status === 409) {
        showToast("bad", "UID déjà enregistré.");
        return;
      }

      showToast("bad", data.message || "Erreur.");
    } catch (e) {
      showToast("bad", "Erreur réseau / API.");
    }
  });

  // Users
  async function loadUsers() {
    usersTableBody.innerHTML = `<tr><td colspan="5" class="muted">Chargement…</td></tr>`;
    try {
      const res = await api("/api/rfid/users", { method: "GET" });
      const data = await res.json().catch(() => ({}));

      if (res.status === 403) {
        usersTableBody.innerHTML = `<tr><td colspan="5" class="muted">Accès refusé (admin requis).</td></tr>`;
        return;
      }

      const rows = data.rows || [];
      if (!rows.length) {
        usersTableBody.innerHTML = `<tr><td colspan="5" class="muted">Aucune carte enregistrée.</td></tr>`;
        return;
      }

      usersTableBody.innerHTML = rows.map((r) => {
        return `
          <tr>
            <td>${r.id}</td>
            <td>${r.full_name}</td>
            <td class="mono">${r.uid}</td>
            <td>${r.enabled ? "Oui" : "Non"}</td>
            <td><button class="btn danger" data-del="${r.id}">Supprimer</button></td>
          </tr>
        `;
      }).join("");

      usersTableBody.querySelectorAll("[data-del]").forEach((btn) => {
        btn.addEventListener("click", async () => {
          const id = btn.getAttribute("data-del");
          try {
            const res2 = await api(`/api/rfid/users/${id}`, { method: "DELETE" });
            const d2 = await res2.json().catch(() => ({}));
            if (res2.status === 200 && d2.success) {
              showToast("ok", "Supprimé.");
              loadUsers();
            } else if (res2.status === 403) {
              showToast("bad", "Admin requis.");
            } else {
              showToast("bad", d2.message || "Erreur.");
            }
          } catch {
            showToast("bad", "Erreur réseau / API.");
          }
        });
      });
    } catch (e) {
      usersTableBody.innerHTML = `<tr><td colspan="5" class="muted">Erreur (API manquante ?).</td></tr>`;
    }
  }

  refreshUsersBtn.addEventListener("click", loadUsers);

  // Initial load
  setDot("warn");
  statusText.textContent = "En attente…";
  await loadLogs();
  await loadUsers();
});
setInterval(() => {
  loadLogs();
}, 1000);

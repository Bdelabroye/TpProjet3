document.addEventListener("DOMContentLoaded", async () => {
  const subtitle = document.getElementById("subtitle");
  const dot = document.getElementById("dot");
  const statusText = document.getElementById("statusText");
  const sessionText = document.getElementById("sessionText");
  const lastCheck = document.getElementById("lastCheck");
  const timeNow = document.getElementById("timeNow");
  const logoutBtn = document.getElementById("logout");
  const goRfid = document.getElementById("goRfid");

  function nowStr() {
    return new Date().toLocaleString();
  }

  function setState(state, text, sub) {
    statusText.textContent = text;
    if (sub) subtitle.textContent = sub;

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

  // horloge
  timeNow.textContent = nowStr();
  setInterval(() => (timeNow.textContent = nowStr()), 1000);

  // logout
  logoutBtn.addEventListener("click", () => {
    localStorage.removeItem("token");
    window.location.href = "/front/index.html";
  });

  // bouton RFID (désactivé tant que la page existe pas)
  // si tu crées plus tard /front/rfid.html, ça s'activera auto
  fetch("/front/rfid.html", { method: "HEAD" })
    .then((r) => { if (r.ok) goRfid.disabled = false; })
    .catch(() => {});
  goRfid.addEventListener("click", () => {
    window.location.href = "/front/rfid.html";
  });

  // validation token
  const token = localStorage.getItem("token");
  if (!token) {
    window.location.replace("/front/index.html");
    return;
  }

  setState("warn", "Vérification…", "Vérification du token…");
  lastCheck.textContent = nowStr();

  try {
    const res = await fetch("/api/auth/validate", {
      method: "GET",
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/json",
      },
    });

    lastCheck.textContent = nowStr();

    if (res.status === 200) {
      const data = await res.json().catch(() => ({}));

      setState("ok", "Connecté", "Token valide. Accès autorisé.");
      // on affiche un truc simple, sans exposer le token
      const user = data?.user?.login || data?.login || "Utilisateur";
      sessionText.textContent = user;
      return;
    }

    // token invalide
    localStorage.removeItem("token");
    setState("bad", "Session expirée", "Token invalide ou expiré. Redirection…");
    sessionText.textContent = "—";

    setTimeout(() => {
      window.location.replace("/front/index.html");
    }, 900);
  } catch (err) {
    localStorage.removeItem("token");
    setState("bad", "Erreur réseau", "Impossible de valider la session. Redirection…");
    sessionText.textContent = "—";
    lastCheck.textContent = nowStr();

    setTimeout(() => {
      window.location.replace("/front/index.html");
    }, 900);
  }
});

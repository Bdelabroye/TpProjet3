document.addEventListener("DOMContentLoaded", async () => {
  const token = localStorage.getItem("token");
  if (!token) {
    window.location.replace('/front/index.html');
    return;
  }

  try {
    const res = await fetch('/api/auth/validate', {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/json'
      }
    });

    if (res.status === 200) {
      // token valide : on peut récupérer des infos si besoin
      const data = await res.json();
      console.log('Token valide', data);
    } else {
      // token invalide ou expiré
      localStorage.removeItem('token');
      window.location.replace('/front/index.html');
    }
  } catch (err) {
    console.error('Erreur de validation du token', err);
    localStorage.removeItem('token');
    window.location.replace('/front/index.html');
  }
});

document.getElementById("logout").addEventListener("click", function() {
    localStorage.removeItem("token");
    window.location.href = '/front/index.html';
});


document.addEventListener('DOMContentLoaded', function() {
    const signupForm = document.getElementById('signupForm');
    
    if (signupForm) {
        signupForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const prenom = document.getElementById('Surname').value;
            const nom = document.getElementById('Name').value;
            const email = document.getElementById('Mail').value;
            const username = document.getElementById('Login').value;
            const password = document.getElementById('Password').value;
            const messageDiv = document.getElementById('message');
            
            try {
                const response = await fetch('/api/inscription', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ prenom: prenom, nom: nom, email: email, username: username, password: password })
                });
                
                if (!response.ok) {
                    messageDiv.textContent = `Erreur serveur : ${response.status} (${response.statusText})`;
                    return;
                }
                
                let result;
                try {
                    result = await response.json();
                } catch (jsonErr) {
                    messageDiv.textContent = "La réponse du serveur n'est pas du JSON.";
                    return;
                }
                
                if (result.success) {
                    messageDiv.textContent = "Inscription réussie ! Connecte-toi.";
                    if(result.token){
                        localStorage.setItem("token", result.token);
                    }
                    setTimeout(() => {
                        window.location.href = '/front/index.html';
                    }, 500);
                } else {
                    messageDiv.textContent = result.message || "Erreur lors de l'inscription.";
                }
                
            } catch (err) {
                messageDiv.textContent = `Erreur de connexion : ${err}`;
            }
        });
    }
});
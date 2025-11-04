require('dotenv').config();
const express = require('express');
const cors = require('cors');
const fs = require('fs');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken')

// On initialise l'application Express
const JWT_SECRET = process.env.JWT_SECRET;

const app = express();

app.use(cors()); // Permet d'autoriser les requêtes cross-origin (REACT)
app.use(express.json()) // Permet d'analyser le corps des requêtes en JSON
// On définit le port sur lequel notre serveur va écouter
const PORT = 4000; // On choisit 4000 pour l'API (React utilise souvent 3000)


// ICI les futures routes ( point d'entrée)
//--

// Route d'inscription
app.post('/subscription', (req,res) => {
    const { email, password } = req.body;
fs.readFile('users.json', 'utf8', async (error, data) => {
    if (err) {
        console.error(err);
        return res.status(500).send('Erreur lors de la lecture des utilisateurs.')
    }

    const users = JSON.parse(data);

    const userExists = users.find(user => user.email === email)
    if (userExists) {
        return res.status(400).send('Cet email est déjà utilisé.')
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = {
        id: users.length + 1,
        email: email,
        password: hashedPassword
    };

    users.push(newUser);

    fs.writeFile('users.json', JSON.stringify(users, null, 2), (writeErr) => {
        if (writeErr) {
            console.error(writeErr);
            return res.status(500).send('Erreur lors de l\'enregistrement du nouvel utilisateur')
        }

        res.status(201).send('Utilisateur créé avec succès !')
    })
})
    console.log("Requête reçue sur /subscription");
    console.log("Corps de la requête :", req.body);
    res.send('Inscription bientôt fonctionnelle !');
});

app.post('/connexion', async (req,res) => {
const { email, password } = req.body;

fs.readFile('users.json', 'utf8', async (err, data) => {
    if (err) {
        console.error(err);
        return res.status(500).send('Erreur lors de la lecture des utilisateurs')
    }

    const users = JSON.parse(data);

    const user = users.find(u => u.email === email);

    if (!user) {
        return res.status(404).send('Email ou mot de passe incorrect.');
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
        return res.status(401).send('Email ou mot de passe incorrect.');
    }

    const token = jwt.sign(
        { id: user.id, email: user.email },
        JWT_SECRET,
        {expiresIn: '1h' }
    );

    res.status(200).json({
        message: 'Connexion réussie !',
        token: token
    })
})
    console.log("Requête reçue sur /connexion");
    console.log("Corps de la requête :", req.body);
    res.send('Connexion bientôt fonctionnelle !');
});
// On met le serveur en écoute sur le port défini
app.listen(PORT, () => {
  console.log(`🤖 Serveur API lancé sur http://localhost:${PORT}`);
});
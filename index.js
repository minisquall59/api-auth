require('dotenv').config();
const express = require('express');
const cors = require('cors');
const fs = require('fs');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 4000;
const filePath = 'users.json';
const JWT_SECRET = process.env.JWT_SECRET || 'secret_fallback'; // Sécurité minimale

app.use(cors());
app.use(express.json());

// ✅ Route d’inscription
app.post('/subscription', (req, res) => {
  const { name, firstname, address, zipcode, city, phone, email, usertype, levelexperiency, timerequired, diet, subscription, PaymentMethod, password } = req.body;

  if (!email || !password) {
    return res.status(400).send('Email et mot de passe sont requis.');
  }

  fs.readFile(filePath, 'utf8', async (error, data) => {
    if (error) {
      console.error(error);
      return res.status(500).send('Erreur lors de la lecture des utilisateurs.');
    }

    const users = JSON.parse(data || '[]');

    if (users.find(user => user.email === email)) {
      return res.status(400).send('Cet email est déjà utilisé.');
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = {
      id: users.length ? users[users.length - 1].id + 1 : 1,
      name,
      firstname,
      address,
      zipcode,
      city,
      phone,
      email,
      password: hashedPassword,
      usertype,
      levelexperiency,
      timerequired,
      diet,
      subscription,
      PaymentMethod,
    };

    users.push(newUser);

    fs.writeFile(filePath, JSON.stringify(users, null, 2), (writeErr) => {
      if (writeErr) {
        console.error(writeErr);
        return res.status(500).send('Erreur lors de l\'enregistrement du nouvel utilisateur.');
      }

      res.status(201).send('Utilisateur créé avec succès !');
    });
  });
});

// ✅ Route de mise à jour
app.patch('/api/users/:id', (req, res) => {
  const idChanged = Number(req.params.id);
  const newData = req.body;

  fs.readFile(filePath, 'utf8', (error, data) => {
    if (error) return res.status(500).send('Erreur lors de la lecture du fichier.');

    let users;
    try {
      users = JSON.parse(data);
    } catch {
      return res.status(500).send('Erreur lors de l\'analyse du fichier JSON.');
    }

    const user = users.find(u => u.id === idChanged);
    if (!user) return res.status(404).send('Utilisateur non trouvé.');

    Object.assign(user, newData);

    fs.writeFile(filePath, JSON.stringify(users, null, 2), (writeErr) => {
      if (writeErr) return res.status(500).send('Erreur lors de l\'enregistrement des modifications.');
      res.status(200).send('Modification effectuée avec succès !');
    });
  });
});

// ✅ Route de suppression
app.delete('/api/users/:id', (req, res) => {
  const idDelete = Number(req.params.id);

  fs.readFile(filePath, 'utf8', (error, data) => {
    if (error) return res.status(500).send('Erreur lors de la lecture du fichier.');

    let users;
    try {
      users = JSON.parse(data);
    } catch {
      return res.status(500).send('Erreur lors de l\'analyse du fichier JSON.');
    }

    const user = users.find(u => u.id === idDelete);
    if (!user) return res.status(404).send('Utilisateur non trouvé.');

    const newUsers = users.filter(u => u.id !== idDelete);

    fs.writeFile(filePath, JSON.stringify(newUsers, null, 2), (writeErr) => {
      if (writeErr) return res.status(500).send('Erreur lors de l\'enregistrement.');
      res.status(200).send('Suppression effectuée avec succès !');
    });
  });
});

// ✅ Route de connexion
app.post('/connexion', async (req, res) => {
  const { email, password } = req.body;

  fs.readFile(filePath, 'utf8', async (err, data) => {
    if (err) return res.status(500).send('Erreur lors de la lecture des utilisateurs.');

    const users = JSON.parse(data || '[]');
    const user = users.find(u => u.email === email);
    if (!user) return res.status(404).send('Email ou mot de passe incorrect.');

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.status(401).send('Email ou mot de passe incorrect.');

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });

    res.status(200).json({ message: 'Connexion réussie !', token });
  });
});

// ✅ Lancement du serveur
app.listen(PORT, () => {
  console.log(`🤖 Serveur API lancé sur http://localhost:${PORT}`);
});

const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const User = require('../models/User');

// Form Register
router.get('/register', (req, res) => {
    res.render('register', { error: null });
});

// Proses Register
router.post('/register', async (req, res) => {
    try {
        const { username, password, email } = req.body;

        console.log('Request body:', req.body); // Tambahkan log ini untuk debugging

        if (!username || !password || !email) {
            return res.status(400).render('register', { error: 'Please fill out all fields' });
        }

        const existingUser = await User.findOne({ where: { username } });

        if (existingUser) {
            return res.status(400).render('register', { error: 'Username already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = await User.create({ username, password: hashedPassword, email });

        if (process.env.NODE_ENV === 'test') {
            res.status(200).json({
                message: 'User successfully added!',
                user: newUser
            });
        } else {
            res.redirect('/users/login');
        }
    } catch (error) {
        console.error('Error during registration:', error); // Tambahkan log ini untuk debugging
        res.status(500).render('register', { error: 'Internal Server Error' });
    }
});

// Form Login
router.get('/login', (req, res) => {
    res.render('login', { error: null });
});

// Proses Login
router.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: 'Please fill out all fields' });
        }

        const user = await User.findOne({ where: { username } });

        if (user && await bcrypt.compare(password, user.password)) {
            req.session.userId = user.id; // Simpan userId di sesi
            req.session.userRole = user.role; // Simpan role di sesi

            if (process.env.NODE_ENV === 'test') {
                res.status(200).json({
                    message: 'Login berhasil!',
                    user: user
                });
            } else {
                res.redirect('/');
            }
        } else {
            res.status(401).json({ message: 'Kredensial tidak valid!' });
        }
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Logout
router.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Error during logout:', err);
            if (process.env.NODE_ENV === 'test') {
                return res.status(500).json({ message: 'Internal Server Error' });
            } else {
                return res.status(500).render('login', { error: 'Internal Server Error' });
            }
        }

        if (process.env.NODE_ENV === 'test') {
            res.status(200).json({ message: 'Logout berhasil!' });
        } else {
            res.redirect('/users/login');
        }
    });
});

module.exports = router;

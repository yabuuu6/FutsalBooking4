const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const session = require('express-session');
const path = require('path');
require('dotenv').config();

const { Sequelize } = require('sequelize');
const sequelize = new Sequelize(process.env.DATABASE_URL, {
    dialect: 'mysql',
    dialectOptions: {
        charset: 'utf8mb4'
    }
});

const { authMiddleware, isAdmin } = require('./middleware/authMiddleware');

const app = express();
const PORT = process.env.PORT || (process.env.NODE_ENV === 'test' ? 3001 : 1000);

// Set view engine to EJS
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({ secret: 'secret', resave: false, saveUninitialized: true }));

sequelize.sync()
    .then(() => console.log('Database connected and synced...'))
    .catch(err => console.log('Error: ' + err));

// Middleware for sessions and user information
app.use((req, res, next) => {
    res.locals.session = req.session;
    res.locals.userId = req.session.userId;
    res.locals.userRole = req.session.userRole;
    next();
});

// Middleware to serve static files from assets
app.use('/assets', express.static(path.join(__dirname, 'assets')));

// Routes for login and register
app.use('/users', require('./routes/users'));

// Middleware to check if the user is authenticated
app.use(authMiddleware);

// Routes for bookings and payments
app.use('/bookings', require('./routes/bookings'));
app.use('/payments', require('./routes/payments'));

// Default route to render home page
app.get('/', (req, res) => {
    res.render('home'); // Assuming you have a 'home.ejs' view
});

// Logout route
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Error during logout:', err);
            return res.status(500).render('login', { error: 'Internal Server Error' });
        }
        res.clearCookie('connect.sid');
        res.redirect('/users/login');
    });
});

// Start the server
if (process.env.NODE_ENV !== 'test') {
    app.listen(PORT, () => {
        console.log(`Server is running on http://localhost:${PORT}`);
    });
}

module.exports = app;

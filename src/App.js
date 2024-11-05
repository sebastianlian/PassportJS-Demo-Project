require('dotenv').config({ path: `${__dirname}/../.env` });

const express = require('express');
const session = require('express-session');
const exphbs = require('express-handlebars');
const mongoose = require('mongoose');
const passport = require('passport');
const localStrategy = require('passport-local');
const bcrypt = require('bcrypt');
const path = require('path');

const app = express();
const User = require('./models/userModel');
const res = require("express/lib/response");

console.log('Database Token:', process.env.databaseToken); // Debug line
mongoose.connect(process.env.databaseToken);

// Set the views directory
app.set('views', path.join(__dirname, 'views'));

// Middleware
const hbs = exphbs.create({ extname: '.hbs' }); // Create instance of Handlebars
app.engine('hbs', hbs.engine); // Use hbs.engine
app.set('view engine', 'hbs'); // Set engine
app.use(express.static(__dirname + '/public'));
app.use(session({
    secret: process.env.secretKey,
    resave: false,
    saveUninitialized: true,
}));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// Passport.js
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser(function (user, done) {
    done(null, user.id);
});

passport.deserializeUser(async function (id, done) {
    try {
        const user = await User.findById(id); // Use await
        done(null, user);
    } catch (err) {
        done(err);
    }
});


passport.use(new localStrategy(async (userName, password, done) => {
    try {
        const user = await User.findOne({ username: userName });
        if (!user) return done(null, false, { message: 'Incorrect Username.' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return done(null, false, { message: 'Incorrect Password.' });

        return done(null, user);
    } catch (err) {
        return done(err);
    }
}));


// Function
function isLoggedIn(req, res, next) {
    if (req.isAuthenticated()) return next();
    res.redirect('/login');
}

function isLoggedOut(req, res, next) {
    if (!req.isAuthenticated()) return next();
    res.redirect('/');
}

// Routes
app.get('/', isLoggedIn, (req, res) => {
    res.render("index", { title: "Home" });
});

app.get('/login', isLoggedOut, (req, res) => {
    const response = {
        title: "Login",
        error: req.query.error
    }

    res.render('login', response);
});

// For other users
app.post('/login', passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login?error=true'
}));

app.get('/logout', function (req, res, next) {
    req.logout(function(err) {
        if (err) { return next(err); } // Handle error
        res.redirect('/'); // Redirect to home after logout
    });
});


// Setup our first admin user
app.get('/setup', async (req, res) => {
    const exists = await User.exists({ username: "admin" });

    if (exists) {
        res.redirect('/login');
        return;
    }

    bcrypt.genSalt(10, function (err, salt) {
        if (err) return next(err);
        bcrypt.hash("pass", salt, function (err, hash) {
            if (err) return next(err);

            const newAdmin = new User({
                username: "admin",
                password: hash
            });

            newAdmin.save();

            res.redirect('/login');
        });
    });
});

app.listen(3000, ()=> {
    console.log('Listening on port 3000');
});


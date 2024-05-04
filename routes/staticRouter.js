const express = require('express');
const flash = require('express-flash');
const fs = require('fs');
const { mlResults } = require('../controllers/public');

const router = express.Router();

router.get('/', (req, res) => {
    return res.render('home', { messages: req.flash() });
});

router.get('/auth', (req, res) => {
    // Check if the 'type' query parameter is present
    const type = req.query.type;
    if (type === 'login') {
        // If type is 'login', render the login page
        return res.render('auth', { isLoginPage: true, messages: req.flash() });
    } else if (type === 'signup') {
        // If type is 'signup', render the signup page
        return res.render('auth', { isLoginPage: false, messages: req.flash() });
    } else {
        // If no type is specified, render the default login page
        return res.render('auth', { isLoginPage: true, messages: req.flash() });
    }
});

router.get('/result', mlResults);

module.exports = router;
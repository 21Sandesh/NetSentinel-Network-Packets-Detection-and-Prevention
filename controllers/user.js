const bcrypt = require('bcrypt');
const { validationResult } = require('express-validator');
const {v4: uuidv4} = require('uuid');
const fetch = require('node-fetch');
const flash = require('express-flash');
const session = require('express-session');
const { stopCapture } = require('../services/capture');
require('dotenv').config();


const User = require('../models/user');
const UserActivity = require('../models/userActivity');
const {setUser} = require('../services/auth');

const AuthSecretKey = process.env.AuthSecretKey;


async function handleUserSignup(req, res) {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        req.flash('error', 'Invalid signup data. Please check your inputs.');
        return res.redirect('/auth');
    }

    const { username, email, password, recaptchaSignupResponse } = req.body;

    const isCaptchaValid = await verifyRecaptcha(recaptchaSignupResponse);
    
    if (!isCaptchaValid) {
        req.flash('error', 'reCAPTCHA verification failed. Please try again.');
        return res.redirect('/auth');
    }

    const existingEmail = await User.findOne({ email });
    if (existingEmail) {
        req.flash('error', 'Email is already registered. Please use another email.');
        return res.redirect('/auth');
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await User.create({
        username,
        email,
        password: hashedPassword,
    });

    req.flash('success', 'Account created successfully.');
    await UserActivity.create({
        username: username,
        ipAddress: normalizeIPAddress(req.headers['x-forwarded-for'] || req.connection.remoteAddress),
        port: req.connection.remotePort,
        action: 'signup'
    });
    
    return res.redirect('/auth');
}

async function handleUserLogin(req, res) {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        req.flash('error', errors.array());
        return res.redirect('/auth');
    }

    const { emailOrUsername, password, recaptchaLoginResponse } = req.body;

    // Verify reCAPTCHA token
    const isCaptchaValid = await verifyRecaptcha(recaptchaLoginResponse);
    if (!isCaptchaValid) {
        req.flash('error', 'reCAPTCHA verification failed. Please try again.');
        return res.redirect('/auth');
    }

    try {
        // console.log('Attempting login with:', emailOrUsername);

        const user = await User.findOne({
            $or: [
                { email: emailOrUsername },
                { username: emailOrUsername }
            ]
        });

        // console.log('User found:', user);

        if (!user || !(await bcrypt.compare(password, user.password))) {
            req.flash('error', 'Invalid email/username or password');
            // console.log('Invalid email/username or password');
            return res.redirect('/auth');
        }

        // Login successful
        const sessionID = uuidv4();
        setUser(sessionID, user);
        res.cookie('sessionID', sessionID); // Set session ID in cookies

        req.flash('success', 'Logged in successfully.');

        await UserActivity.create({
        username: user.username,
        ipAddress: normalizeIPAddress(req.headers['x-forwarded-for'] || req.connection.remoteAddress),
        port: req.connection.remotePort,
        action: 'login'
    });
        return res.redirect('/user/dashboard');
    } catch (error) {
        // console.error('Error during login:', error);
        req.flash('error', 'An error occurred during login. Please try again.');
        return res.redirect('/auth');
    }
}

async function handleUserLogout(req, res) {
    res.clearCookie('sessionID');
    stopCapture();

    req.flash('success', 'Logged out successfully.');

    await UserActivity.create({
        username: req.user.username,
        ipAddress: normalizeIPAddress(req.headers['x-forwarded-for'] || req.connection.remoteAddress),
        port: req.connection.remotePort,
        action: 'logout'
    });
    
    return res.redirect('/');
}

async function verifyRecaptcha(token) {
    const secretKey = AuthSecretKey;

    const url = `https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${token}`;
    // console.log('url:', url);

    try {
        const response = await fetch(url, { method: 'POST' });
        const data = await response.json();
        return data.success;
    } catch (error) {
        // console.error('Error verifying reCAPTCHA:', error);
        return false;
    }
}

function normalizeIPAddress(ip) {
    // If IP is IPv6 local, return IPv4 local
    if (ip === '::1') {
        return '127.0.0.1';
    }

    // If IP is IPv6, convert to IPv4 format
    if (ip.includes(':')) {
        const parts = ip.split(':');
        return parts[parts.length - 1];
    }

    return ip;
}

module.exports = {
    handleUserSignup,
    handleUserLogin,
    handleUserLogout,
}


const express = require('express');
const { handleUserSignup, handleUserLogin } = require('../controllers/user');
const router = express.Router();
const { check } = require('express-validator');

const { validateInputs } = require('../middlewares/validation');

const signupValidationRules = [
    check('username').notEmpty(),
    check('email').isEmail(),
    check('password').isLength({ min: 8 }),
    validateInputs,
];
const loginValidationRules = [
    check('emailOrUsername'),
    check('password').isLength({ min: 8 }),
    validateInputs,
];

router.post('/signup', signupValidationRules, handleUserSignup);
router.post('/login', loginValidationRules, handleUserLogin);

module.exports = router;
const { validationResult } = require('express-validator');

const validateInputs = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        req.flash('DataSiteKey', process.env.DataSiteKey);
        return res.redirect("/auth")
    }
    next();
};

module.exports = { validateInputs };

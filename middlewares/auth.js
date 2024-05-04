const {getUser} = require("../services/auth");

async function restrictAccess(req, res, next){
    const sessionID = req.cookies.sessionID;
    if (!sessionID) {
        req.flash('DataSiteKey', process.env.DataSiteKey);
        return res.redirect("/auth");
    }

    const user = getUser(sessionID);

    if (!user) {
        req.flash('DataSiteKey', process.env.DataSiteKey);
        return res.redirect("/auth");
    }

    req.user = user;
    next();
}

module.exports = {
    restrictAccess,
}
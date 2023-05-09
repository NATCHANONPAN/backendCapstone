const JWT = require('jsonwebtoken');

const config = process.env;

const verifyToken = (req, res, next) => {
    // console.log(req.body);
    // console.log(req.file);
    const token = req.body.token || req.query.token || req.body['x-access-token'] || req.headers['x-access-token'];

    if (!token) {
        return res.status(403).send("A token is required for authentication");
    }

    try {
        const decoded = JWT.verify(token, config.TOKEN_KEY);
        req.user = decoded;
    } catch(err) {
        return res.status(401).send("Invalid token"); 
    }

    return next();
}

module.exports = verifyToken;
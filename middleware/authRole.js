const JWT = require('jsonwebtoken');

const authRole = (permissions) => {
    return (req, res, next) => {
        // const userRole = req.body.role
        const token = req.headers['x-access-token'];
        const data = JWT.decode(token)
        // console.log(data);
        if (permissions.includes(data.userRole)) {
            next()
        } else {
            return res.status(401).json("You don't have permission!");
        }
    }
};

module.exports = {authRole};

'use strict';
const debug = require('debug')('transom:mongoose:localuser:jwt');
const jwt = require('jsonwebtoken');

module.exports = function JwtUtils(options) {

    /**
     * Simple function to create consistent JWT's from /login and refresh
     */
    // this.userToJwt = result => {
    //     const issued = new Date();
    //     const jwtExpirySeconds = 60 * 60; // 1 hour
    //     const user = {
    //         _id: result._id,
    //         username: result.UserId,
    //         name: result.Name,
    //         email: result.Email
    //     };
    //     // TODO: remove manual; issed date checking, use "maxAge: n(seconds)" instead!
    //     const token = jwt.sign({ user, issued }, JWT_TOKEN_SECRET, 
    //         {
    //             algorithm: "HS256",
    //             expiresIn: jwtExpirySeconds
    //         });
    //     return { token };
    // };

    this.payloadRequiredAttribs = (token) => {
        // Make sure that the JWT has all the necessary fields.
        const requiredFields = ["_id", "display_name", "username", "email"];

        return new Promise((resolve, reject) => {
            requiredFields.forEach((f) => {
                if (!token[f]) {
                    return reject(`Developer error: Required attribute missing from the JWT: ${f}`);
                }
            });
            return resolve(token);
        });
    }

    this.cookieExtractor = (cookieName) => {
        return (request) => {
            let token = null;
            if (request.cookies[cookieName]) {
                token = request.cookies[cookieName];
            }
            return token;
        };
    };

}
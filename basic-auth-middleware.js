
'use strict';
const base64 = require('base-64');
const users = require('./users.js/index.js');
//middle-ware function 
let basicAuthMiddleware=function (req,res,next) {
    //req.headers.authorization is hashed password and username
    if(!req.headers.authorization){ next('cannot login'); return;}
    // split is convert from string to an array 
    let basicAuth = req.headers.authorization.split(' ').pop();
    console.log('req.headers.authorization',req.headers.authorization)
    console.log('basicAuth',basicAuth)
    //['dania','12345']
    let [user,password] = base64.decode(basicAuth).split(':');
    console.log('[user,password] ',[user,password] )
    // it will be comparing the password and it will return username
    users.basicOfAuthenticate(user,password)
    .then(goodUser=>{
        // create a token to the request , the token will authorize me to access to specific route
        req.token=users.tokenGeneration(goodUser)
        console.log('token',req.token)
        next();
    }).catch(err=> next('cannot login'));
}
module.exports=basicAuthMiddleware;
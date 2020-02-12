

const base64 = require('base-64');
const users = require('./users.js');
//middle-ware function
let basicAuthMiddleware = function (req,res,next) {
  //req.headers.authorization is hashed password and username
  if(!req.headers.authorization){ next('cannot login'); return;}
  // split is convert from string to an array
  let basicAuth = req.headers.authorization.split(' ').pop();
  console.log('req.headers.authorization',req.headers.authorization);
  console.log('basicAuth',basicAuth);
  //['dania','12345']
  let [user,password] = base64.decode(basicAuth).split(':');
  console.log('[user,password] ',[user,password] );
  let auth = {user , password};
  console.log('auth',auth);

  // it will be comparing the password and it will return username
  users.auth(auth)
    .then(goodUser=>{
      // create a token to the request , the token will authorize me to access to specific route
      req.token = users.tokenGenerationForSignin(goodUser);
      console.log('token',req.token);
      next();
    });
  // .catch(err=> next('cannotlogin'));
};
module.exports = basicAuthMiddleware;
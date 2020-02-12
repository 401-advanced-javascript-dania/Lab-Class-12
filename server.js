
'use stirct';
const express = require('express');
const basicOfAuth = require('./basic-auth-middleware.js');
const oauthMiddleware = require('./oauth-middleware.js')
const Users = require('./users.js');
const app = express();
//global middleware
app.use(express.json());
app.use(express.static('./public'))
// signup that it will be to the first time the user sign into the app (creation peise)
app.post('/signup',(req,res)=>{
  //req.body have a basic information (user information)
  //it will create an object with username and hashed password
  let users = new Users(req.body);
  users.save()
  // users.userInfoSave(req.body)
  // it an extra code no need for it , it will just show us the token
    .then(username=>{
      req.token = username.tokenGenerationForSignup(username);
      req.user = username;
      res.status(200).json(req.token);
    });
});
// basicOfAuth is route level middleware
// in signin it will take the password and decode it with base64 and make sure that is a 1.valid user then it will let him or her to access to the app 2. generate a token
app.post('/signin',basicOfAuth,(req,res)=>{
  // it an extra code no need for it , it will just show us the token

  res.status(200).send(req.token);
});
// it will reutrn the all database
app.get('/users',basicOfAuth,(req,res)=>{
  res.status(200).json(users.list());
});

app.get('/oauth',oauthMiddleware,(req,res,next)=>{
    res.status(200).json(req.token)
})
module.exports = {
  server:app,
  start: port =>{
    let PORT = port || process.env.PORT || 3000;
    app.listen(PORT,()=>console.log(`server up on ${PORT}`));
  },
};
'use strict';
require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const base64 = require('base-64');
const jwt = require('jsonwebtoken');
const oauth = require('./oauth-middleware.js');

const app = express();

app.use(express.json());
app.use(express.static('./public'));
let users =  {};
let SECRET =process.env.SECRET;

app.post('/signup',async (req,res)=> {
    let user = req.body;
    if (!users[user.username]){
        user.password = await bcrypt.hash(req.body.password,5)
        users[user.username] = user;
        let token = await jwt.sign({ username:user.username}, SECRET);
        res.status(200).send(token);
    }else{
        res.status(403).send('username taken, sorry')
    }
});
app.post('/signin',async (req,res)=>{
    let basic = req.headers.authorization.split(' ').pop();
    let [user,pass]=base64.decode(basic).split(':');
    let verfied = users[user] ? await bcrypt.compare(pass, users[user].password) : false;
    if (verfied){
        let token = jwt.sign({ username: user.username},SECRET);
        res.status(200).send(token);
    }else{
        res.status(403).send('Invalid Login');
    }
});
app.get('/users',(req,res)=>{
    res.status(200).json(users);
})
app.get('/oauth',oauth,(req,res)=>{
    res.status(200).send(req.token);
})
app.listen(3000, ()=> console.log('server up'));


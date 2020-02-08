'use strict';
//bcrybt and jwt is two layer of athentication
//to hash the password then compare it 
const bcrypt = require('bcryptjs')
// to generate the token from the username and the SECRET (It will apply another layer security o it)
const jwt = require('jsonwebtoken')
 let SECRET = 'SECRET';
// db it will be the mongo database
 let db = {};
 // user will be the schema 
 let users = {};
 // .save is methode of user and sync to wait until bcrypt done with hashing the password then it will back with the password that hashed
 users.userInfoSave = async function (data) {
     //create a password then hashed password using bcrypt
     // when we save a user that is not exist it will assgin the password to hash password then we will return  an object username and password   
     // the [data.username] is a string like 'dania'
     if(!db[data.username]) {
         data.password = await bcrypt.hash(data.password,5);
         db[data.username] = data;
         return data 
     }
return Promise.reject();
 } 
// the first layer is base64 coded send over the server then hash it then compare it with the password that is saved to the database
 users.basicOfAuthenticate = async function(user,password) {
     //it will take the password that user inter it and the password in the database and it will return the user name 
     let comparePassword = await bcrypt.compare(password,db[user].password)
     return comparePassword ? db[user] : Promise.reject();
 }
// it will generate a token from two factor layer of SECRET and username to authorize 
 users.tokenGeneration = function(user) {
let unique = jwt.sign({username:user.username},SECRET);
return unique;
 }
 // it is a function that will return the all of data user
 users.dataUser=()=>db;
 module.exports=users;
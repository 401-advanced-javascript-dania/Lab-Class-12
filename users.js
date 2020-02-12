  
'use strict';
require('dotenv').config();
const mongoose =require('mongoose');
//bcrybt and jwt is two layer of athentication
//to hash the password then compare it 
const bcrypt = require('bcryptjs')
// to generate the token from the username and the SECRET (It will apply another layer security o it)
const jwt = require('jsonwebtoken')
 let SECRET = process.env.SECRET;
// db it will be the mongo database
//  let db = {};
 // user will be the schema 
//  let users = {};
const users = new mongoose.Schema({
    username: { type:String, required:true},
    password: { type:String,required:true},
});
 // .save is methode of user and sync to wait until bcrypt done with hashing the password then it will back with the password that hashed
 users.pre('save', async function () {
     //create a password then hashed password using bcrypt
     // when we save a user that is not exist it will assgin the password to hash password then we will return  an object username and password   
     // the [data.username] is a string like 'dania'
     if(this.isModified('password')) {
         this.password = await bcrypt.hash(this.password,5);
     }
return Promise.reject();
 } )
 users.statics.auth = function(auth){
     let query = {username: auth.user};
     return this.findOne(query)
      .then(username =>{
          return username.basicOfAuthenticate(auth.password)
      })
 }
// the first layer is base64 coded send over the server then hash it then compare it with the password that is saved to the database
 users.methods.basicOfAuthenticate =  function(password) {
     //it will take the password that user inter it and the password in the database and it will return the user name 
     let comparePassword =  bcrypt.compare(password,this.password)
     return comparePassword
     .then(good =>{
         return good ? this : Promise.reject();
     })
 }
// it will generate a token from two factor layer of SECRET and username to authorize 
 users.statics.tokenGenerationForSignin = function(user) {
let unique = {id: user._id}
return jwt.sign(unique,SECRET);
 }
  users.methods.tokenGenerationForSignup = function(user) {
    let unique = {id: user._id}
    return jwt.sign(unique,SECRET);
     }
 // it is a function that will return the all of data user
//  users.dataUser=()=>db;
 module.exports=mongoose.model('users',users);
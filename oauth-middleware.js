
'use strict';
//oauth  to get back user information 1. give me the access_token from gihub 2. give me the user info
//to take the env enviroment
// require('dotenv').config();
// to handle the remote request from github (API) (request engin)
const superagent = require('superagent');
const users = require('./users.js');
// the url to get a token for access 
const tokenUrl = 'https://github.com/login/oauth/access_token';
// the api that we will be accessing 
const remoteAPI = 'https://api.github.com/user';
const CLIENT_ID='cee7d9c157365d5ea927';
const CLIENT_SECRET='3e000384db3cb375703901435424d41b65fa8c3c';
//our api server (path for get request ) redirect from github 
const API_SERVER='http://localhost:3000/oauth';
module.exports=async function authorize(req,res,next){
    try{
        let code = req.query.code;
        console.log('code',code)
        // give github access_token and give me user Info
        let accessToken = await codeAgainstToken(code);
        console.log('accessToken',accessToken)
        // take the user Info
        let userLargeInfo = await getUserInfo(accessToken);
        // type the user Info and token 
        console.log('userLargeInfo',userLargeInfo)
        let [user,token] = await typeUserInfo(userLargeInfo);
        console.log('[user,token]',[user,token])
        req.user=user;
        req.token=token;
        next();
    }catch(err){
        next(err);
    }
}
async function codeAgainstToken(code){
    // we are return response object and attached it to req.body
    let tokenRes = await superagent.post(tokenUrl).send({
        code:code,
        client_id:CLIENT_ID,
        client_secret:CLIENT_SECRET,
        redirect_uri:API_SERVER,
        grant_type:'authorization_code'
    })
    //tokenRes.body is like req.body
    let access_token = tokenRes.body.access_token;
    return access_token;
}
// once we login with github i give github my access_token and github give me user info 
async function getUserInfo(token){
    let userRes = await superagent.get(remoteAPI)
    //set headers
    .set('user-agent', 'express-app')
    .set('Authorization', `token ${token}`)
    // console.log('userRes',userRes)
let userInfo = userRes.body;
return userInfo;
}
// it type the user information , the user that own that github 
async function typeUserInfo(userName){
    let userData= {
        username:userName.login,
        password:'anything'
    }
    let user = await users.userInfoSave(userData);
    let token = users.tokenGeneration(user);
    return [user,token]
}
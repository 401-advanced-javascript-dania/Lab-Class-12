'use strict ';
require('dotenv').config();
const mongoose = require('mongoose');
const server = require('./server.js');
const MONGODB_URI = process.env.MONGODB_URI;
const PORT = process.env.PORT || 3000;
const mongooseOptions = {
  useNewUrlParser:true,
  useCreateIndex:true,
  useUnifiedTopology:true,
  useFindAndModify:false,
};
mongoose.connect(MONGODB_URI,mongooseOptions);
server.start(PORT);
let express = require('express');
let router = express.Router();
let app = express();
let db = require('./config/db');
let userRoutes = require('./routes/user-routes');
let authRoutes = require('./routes/auth-routes');

// route config
app.use('/users', userRoutes);
app.use('/auth', authRoutes);

module.exports = app;
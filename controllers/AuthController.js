let express = require("express");
var jwt = require("jsonwebtoken");
let bcrypt = require("bcryptjs");
let config = require("../config/config");

let User = require("../models/User");

let register = (req, res) => {
    let hashedPassword = bcrypt.hashSync(req.body.password, 8);

    User.create({
        name : req.body.name,
        email : req.body.email,
        password : hashedPassword
    })
    .then((user) => {
        // create a token
        let token = jwt.sign({id: user._id}, config.secret, {expiresIn: 86400}); // expires in 24 hours
        
        res.status(200).send({auth: true, token: token});
    })
    .catch((err) => res.status(500).send("There was a problem registering the user."));
};

let allowMe = (req, res) => {
    User.findById(req.userId, {password: 0}) // projection exclude password
    .then((user) => {
        if(!user) {
            return res.status(404).send("No user found.");
        }
        res.status(200).send(user);
    })
    .catch((err) => res.status(500).send("There was a problem finding the user."));
};

let login = (req, res) => {

    User.findOne({email: req.body.email})
    .then((user) => {
        if(!user) {
            return res.status(404).send("No user found.");
         }

         let passwordIsValid = bcrypt.compareSync(req.body.password, user.password);
         if(!passwordIsValid) {
             return res.status(401).send({auth: false, token: null});
         }

         let token = jwt.sign({id: user._id}, config.secret, {expiresIn: 86400 }); //  expires in 24 hours

         res.status(200).send({auth: true, token: token});
    })
    .catch((err) => res.status(500).send("Error on the server."));
};

let logout = (req,res) => {
    res.status(200).send({auth: false, token: null});
};

module.exports = {
    register: register,
    allowMe: allowMe,
    login: login,
    logout: logout
};


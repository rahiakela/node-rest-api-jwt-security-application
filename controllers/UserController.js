let express = require('express');
let router = express.Router();
let bodyParser = require('body-parser');

let User = require('../models/User');

// CREATES A NEW USER
let createNewUser = (req, res) => {
    User.create({
            name : req.body.name,
            email : req.body.email,
            password : req.body.password
        })
        .then((user) => res.status(200).send(user))
        .catch((err) => res.status(500).send("There was a problem adding the information to the database."));
}

// RETURNS ALL THE USERS IN THE DATABASE
let getUsers = (req, res) => {
    User.find({})
    .then((users) => res.status(200).send(users))
    .catch((err) => res.status(500).send("There was a problem finding the users."));
}

// GETS A SINGLE USER FROM THE DATABASE
let getUser = (req, res) => {
    User.findById(req.params.id)
    .then((user) => {
        if (!user) return res.status(404).send("No user found.");
        res.status(200).send(user);
    })
    .catch((err) => res.status(200).send(user));
}

// DELETES A USER FROM THE DATABASE
let deleteUser = (req, res) => {
    User.findByIdAndRemove(req.params.id)
    .then((user) => res.status(200).send("User: "+ user.name +" was deleted.")) 
    .catch((err) => res.status(500).send("There was a problem deleting the user."));
}

// UPDATES A SINGLE USER IN THE DATABASE
let updateUser = (req, res) => {
    User.findByIdAndUpdate(req.params.id, req.body, {new: true})
    .then((user) => res.status(200).send(user))
    .catch((err) => res.status(500).send("There was a problem updating the user."));
}


module.exports = {
    createNewUser: createNewUser,
    getUser: getUser,
    getUsers: getUsers,
    deleteUser: deleteUser,
    updateUser: updateUser
};
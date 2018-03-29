var express = require("express");
let bodyParser = require("body-parser");
var router = express.Router();

var userController = require("../controllers/UserController");

router.use(bodyParser.urlencoded({ extended: true }));
router.use(bodyParser.json());

// CREATES A NEW USER
router.post('/', userController.createNewUser);
// RETURNS ALL THE USERS
router.get('/', userController.getUsers);
// GETS A SINGLE USER
router.get('/:id', userController.getUser);
// DELETES A USER 
router.delete('/:id', userController.deleteUser);
// UPDATES A SINGLE USER 
router.put('/:id', userController.updateUser);

// export the router
module.exports = router;
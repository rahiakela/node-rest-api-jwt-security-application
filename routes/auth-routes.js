let express = require("express");
let bodyParser = require("body-parser");
let router = express.Router();

let authController = require("../controllers/AuthController");
let VerifyToken = require("../auth/VerifyToken");

router.use(bodyParser.urlencoded({ extended: true }));
router.use(bodyParser.json());

router.post("/register", authController.register);
router.get("/me", VerifyToken, authController.allowMe);
router.post("/login", authController.login);
router.get("/logout", authController.logout);

// export the router
module.exports = router;
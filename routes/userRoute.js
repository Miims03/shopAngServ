const express = require("express");
const { registerUser , loginUser, findUser , getUser, confirmEmail} = require("../controllers/userController")
const authenticateToken = require("../middlewares/authMiddleware");

const router = express.Router();

router.get('/confirm-email', confirmEmail)
router.post("/register", registerUser)
router.post("/login", loginUser)
router.get("/find/:id", authenticateToken, findUser)
router.get("/find", authenticateToken, getUser)

module.exports = router;
const express = require("express");
const app = express();
const cors = require("cors");

require('dotenv').config()

app.use(express.json());
app.use(cors())

const userRoute = require("./routes/userRoute")

app.use('/api/users' , userRoute)

app.get("/",  (req, res) => {
    res.send("Welcome to backend");
})

const PORT = process.env.PORT || 3000

app.listen(PORT, (req , res) => {
    console.log(`Serveur sur le port ${PORT}...`);
})


const userModel = require("../models/userModel");
const bcrypt = require('bcryptjs');
const validator = require("validator");
const jwt = require("jsonwebtoken");
const checkEmailValidity = require("../modules/emailCheck");
const { Op } = require('sequelize');
const nodemailer = require('nodemailer');
require('dotenv').config()


const createToken = (id, purpose, time, timeUnit) => {
    const jwtKey = process.env.JWT_SECRET_KEY
    return jwt.sign({ id, purpose: `${purpose}` }, jwtKey, { expiresIn: `${time}${timeUnit}` });
}

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.GMAIL_USER, // Votre adresse Gmail
        pass: process.env.GMAIL_PASSWORD // Le mot de passe ou un mot de passe d'application
    }
});

const sendConfirmationEmail = async (to, token) => {
    const confirmationUrl = `http://localhost:3000/api/users/confirm-email?token=${token}`;
    // Utilisez un service comme nodemailer pour envoyer l'email
    const mailOptions = {
        from: process.env.GMAIL_USER,
        to: to,
        subject: 'Please confirm your email',
        html: `
            <h3>Welcome to YourApp!</h3>
            <p>Please confirm your email by clicking the link below:</p>
            <a href="${confirmationUrl}">Confirm Email</a>
        `
    };
    try {
        await transporter.sendMail(mailOptions);
        console.log('Confirmation email sent successfully to', to);
    } catch (error) {
        console.log('Error sending confirmation email:', error);
    }
};

const confirmEmail = async (req, res) => {
    try {
        // Récupérer le token depuis la requête
        const { token } = req.query;
        // Vérification si le token est fourni
        if (!token) {
            return res.status(400).json('Token is missing');
        }

        // Clé secrète pour décoder le token
        const jwtKey = process.env.JWT_SECRET_KEY;

        // Décodage du token
        const decoded = jwt.verify(token, jwtKey);

        // Vérifier si le token a bien le bon objectif (confirmation de l'email)
        if (decoded.purpose !== 'email-confirmation') {
            return res.status(403).json('Invalid token or expired.');
        }
        
        // Mise à jour de l'utilisateur pour confirmer l'email
        const user = await userModel.update(
            { isEmailConfirmed: true },
            { where: { id: decoded.id } }
        );
        console.log('Decoded token:', decoded);
        if (!user) {
            return res.status(404).json('User not found');
        }

        res.json('Email confirmed successfully!');
        
    } catch (err) {
        console.log(err);
        return res.status(500).json('Error confirming email');
    }
};

const registerUser = async (req, res) => {
    try {
        const { username, email, password, dob, firstname, lastname } = req.body

        const isEmailValid = await checkEmailValidity(email);

        const user = await userModel.findOne({
            where: {
                username: username,
                email: email
            }
        })

        if (user) {
            if (user.username === username)
                return res.status(400).json('Username already registered.')
            if (user.email === email)
                return res.status(400).json('Email already registered.')
        }

        if (!username || !email || !password || !dob || !firstname || !lastname)
            return res.status(400).json('All fields required...')

        if (!validator.isEmail(email))
            return res.status(400).json("Email is not valid...")

        if (!isEmailValid)
            return res.status(400).json("Email does not exist...")



        if (!validator.isStrongPassword(password))
            return res.status(400).json("Password most be strong...")

        const hashedPassword = await bcrypt.hash(password, 10);

        // const now = moment().tz('Europe/Paris')

        const newUser = await userModel.create({
            username: username,
            email: email,
            password: hashedPassword,
            dob: dob,
            firstname: firstname,
            lastname: lastname,
            isEmailConfirmed: false
        });


        const token = createToken(newUser.id, 'email-confirmation', '15', 'm')

        await sendConfirmationEmail(newUser.email, token);

        res.status(200).json({ id: newUser, token })

    } catch (err) {
        console.log(err)
        res.status(500).json(err)
    }
}

const loginUser = async (req, res) => {

    const { username, email, password } = req.body

    if ((!username && !email) || !password) {
        return res.status(400).json('Username/email and password are required');
    }

    try {

        const user = await userModel.findOne({
            where: {
                [Op.or]: [
                    { email: email || null },
                    { username: username || null }
                ]
            }
        })

        if (!user)
            return res.status(400).json('Invalid username / email or password')

        const isPasswordValid = await bcrypt.compare(password, user.password)

        if (!isPasswordValid)
            return res.status(400).json('Invalid username / email or password')

        const token = createTokenConfirmation(user.id, 'auth', '1', 'd')

        res.status(200).json({
            id: user.id,
            username: user.username,
            email: user.email,
            token
        })

    } catch (err) {
        console.log(err)
        res.status(500).json(err)
    }
}

const findUser = async (req, res) => {

    const userId = req.params.id

    try {
        const user = await userModel.findByPk(userId)
        res.status(200).json(user)
            .username, user.email

    } catch (err) {
        console.log(err)
        res.status(500).json(err)
    }

}

const getUser = async (req, res) => {
    try {
        const user = await userModel.findAll()
        res.status(200).json(user)

    } catch (err) {
        console.log(err)
        res.status(500).json(err)
    }

}

module.exports = {
    confirmEmail,
    registerUser,
    loginUser,
    findUser,
    getUser
}
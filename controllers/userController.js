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
    const confirmationUrl = `http://localhost:4200/confirm?token=${token}`;
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
        const { token } = req.query;

        if (!token) {
            return res.status(400).json('Token is missing');
        }

        const jwtKey = process.env.JWT_SECRET_KEY;

        const decoded = jwt.verify(token, jwtKey);

        if (decoded.purpose !== 'email-confirmation') {
            return res.status(403).json('Invalid token or expired.');
        }
        
        const user = await userModel.update(
            { isEmailConfirmed: true },
            { where: { id: decoded.id } }
        );
        console.log('Decoded token:', decoded);
        if (!user) {
            return res.status(404).json('User not found');
        }

        res.status(200).json('Email confirmed successfully!');
        
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
                [Op.or]: [
                    { email: email || null },
                    { username: username || null }
                ]
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

        const newUser = await userModel.create({
            username: username,
            email: email,
            password: hashedPassword,
            dob: dob,
            firstname: firstname,
            lastname: lastname,
            isEmailConfirmed: false
        });


        const token = createToken(newUser.id, 'email-confirmation', '1', 'd')

        await sendConfirmationEmail(newUser.email, token);

        res.status(200).json({ id: newUser, token })

    } catch (err) {
        console.log(err)
        console.error("Error during user registration:", err);
        res.status(500).json({ message: "Internal server error", error: err.message });
    }
}

const loginUser = async (req, res) => {

    const { username, email, password, token } = req.body

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

        if (!user.isEmailConfirmed) {
            const newToken = createToken(user.id, 'email-confirmation', '15', 'm');
            
            await sendConfirmationEmail(user.email, newToken);

            return res.status(403).json({
                message: 'Please confirm your email before logging in.',
                tokenExpired: true, // Indiquer au frontend que le token est expiré et un nouvel email a été envoyé
                info: 'A new confirmation email has been sent to your inbox.'
            });
        }

        // if (!token) {
        //     return res.status(400).json('Token is required');
        // }

        // const jwtKey = process.env.JWT_SECRET_KEY;

        // let decoded;
        // try {
        //     decoded = jwt.verify(token, jwtKey);
        // } catch (err) {
        //     return res.status(400).json('Invalid or expired token');
        // }

        // if (decoded.id !== user.id) {
        //     return res.status(403).json('Token does not match the user');
        // }

        await userModel.update(
            { isConnected: true },
            { where: { id: user.id } }
        );

        const newToken = createToken(user.id, 'auth', '1', 'd')

        res.status(200).json({
            id: user.id,
            username: user.username,
            email: user.email,
            token: newToken
        })

    } catch (err) {
        console.log(err)
        res.status(500).json(err)
    }
}

const logoutUser = async (req, res) => {
    try {
        const { token } = req.body; // On récupère le token depuis la requête (peut être dans les headers ou le body)

        if (!token) {
            return res.status(400).json('Token is missing');
        }

        const jwtKey = process.env.JWT_SECRET_KEY;
        
        // Décoder le token pour obtenir l'ID de l'utilisateur
        const decoded = jwt.verify(token, jwtKey);

        // Mettre à jour l'utilisateur pour définir isConnected à false
        const user = await userModel.update(
            { isConnected: false },
            { where: { id: decoded.id } }
        );

        // Si l'utilisateur n'a pas été trouvé
        if (!user) {
            return res.status(404).json('User not found');
        }

        // Réponse en cas de succès
        res.status(200).json('User logged out successfully!');

    } catch (err) {
        console.log(err);
        res.status(500).json('Error logging out user');
    }
};


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
    logoutUser,
    findUser,
    getUser
}
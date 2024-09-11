// user.js
const { DataTypes } = require('sequelize');
const { v4: uuidv4 } = require('uuid');
const database = require('../database'); 

const User = database.define('users', {
    id: {
        type: DataTypes.UUID,
        defaultValue: uuidv4,  // Utilise la fonction uuidv4 pour générer un UUID par défaut
        primaryKey: true,
        allowNull: false,
    },
    username: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true
    },
    email: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true
    },
    password: {
        type: DataTypes.STRING,
        allowNull: false
    },
    dob: {
        type: DataTypes.DATEONLY,
        allowNull: false
    },
    firstname: {
        type: DataTypes.STRING,
        allowNull: false
    },
    lastname: {
        type: DataTypes.STRING,
        allowNull: false
    },
    isEmailConfirmed: {
        type: DataTypes.BOOLEAN,
        defaultValue: false
    },
    isConnected: {
        type: DataTypes.BOOLEAN,
        defaultValue: false
    },
});

database.sync()

module.exports = User;

const { Sequelize } = require('sequelize');

require('dotenv').config()

const DB_URL = process.env.DATABASE_URL


const database = new Sequelize(DB_URL,{dialect: 'mysql2'});

// Test the connection
database.authenticate()
    .then(() => console.log('Connection à la base de données reussi.'))
    .catch(err => console.error('Unable to connect to the database:', err));

module.exports = database
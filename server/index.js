require('dotenv').config();
const express = require('express');
const app = express();
const massive = require('massive');
const session = require('express-session');
const bcrypt = require('bcryptjs');

const { SERVER_PORT, DB_STRING, SESSION_SECRET } = process.env;

app.use(express.json());

app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
        maxAge: 1000 * 60 * 60 * 24
    }
}));

massive(DB_STRING).then(db => {
    app.set('db', db);
    console.log('DB connected');
});

app.post('/auth/register', function(req, res) {
    const { username, password } = req.body;
    const db = req.app.get('db');

    db.checkForUser(username).then(user => {
        if (user.length === 0) { // OK to make as new user
            const salt = bcrypt.genSaltSync(); // generate salt

            bcrypt.hash(password, salt).then(hash => { // then hash the user's pw and our salt
                db.addUser(username, hash).then(response => {
                    console.log(response);
                    
                    req.session.user = {
                        user_id: response[0].user_id,
                        username: username
                    }

                    res.status(200).json(req.session.user);
                })
            });
            // then we'll add our new user to database
        } else { // username already taken
            res.status(409).json({ message: "Username taken. Try again!"})
        }
    })
});

app.post('/auth/login', async function(req, res) {
    const { username, password } = req.body;
    const db = req.app.get('db')

    const user = await db.checkForUser(username);
    bcrypt.compare(password, user[0].hash).then(doesMatch => {
        if (doesMatch) { 
            req.session.user = {
                user_id: user[0].user_id,
                username: username
            }

            res.status(200).json(req.session.user);
        } else {
            res.status(403).json({ message: "Incorrect username or password"})
        }
    })



});

app.listen(SERVER_PORT, () => console.log(`Server listening on ${SERVER_PORT}`))
// Project objective - 
// APIs for storing username/password combinations and authentication

const express = require('express');
const { isAuthorized, createNewUser, setupAuthTable, getApiKeyForUser, findUserByApiKey } = require('./util/helper');

const PORT = 3000;

const app = express();
app.use(express.json()); // json support 
app.use(express.urlencoded({ extended: true })) // urlencoded support

/* SIGN UP -> CREATE NEW USER */
app.post('/create', async (req, res) => {
    if (req.get('Content-Type') != "application/x-www-form-urlencoded") {
        return res.status(406).json({ error: "Request format incorrect, please use Content-Type: application/x-www-form-urlencoded" });
    }

    const username = req.body.username;
    const password = req.body.password;

    console.log("Received request to create user:", username);
    const error_message = await createNewUser(username, password);
    if (error_message != null) {
        return res.status(400).json({ message: error_message });
    }

    return res.status(201).json({ message: `Created user: ${username}` });
});

/* LOGIN -> INPUT USER/PASS -> GET API-KEY -> APPLICATION STORE API-KEY */
app.post('/key', async (req, res) => {
    if (req.get('Content-Type') != "application/x-www-form-urlencoded") {
        return res.status(406).json({ error: "Request format incorrect, please use Content-Type: application/x-www-form-urlencoded" });
    }

    const username = req.body.username;
    const password = req.body.password;

    console.log("Received request to get api_key for user:", username);
    const error_message = await isAuthorized(username, password);
    if (error_message != null) {
        return res.status(401).json({ error: error_message });
    } 

    const user_api_key = await getApiKeyForUser(username);
    return res.status(202).json({ api_key: user_api_key });
});

/* APPLICATION -> AUTHORIZE USER BASED ON API-KEY */
app.post('/authorize', async (req, res) => {
    const api_key = req.get('api_key');

    const user_api_key = await findUserByApiKey(api_key);
    if (user_api_key == null) {
        return res.status(401).json({ authorized: false, reason: "Invalid api_key" });
    }

    return res.status(200).json({ authorized: true });
});

app.listen(PORT, function (err) {
    if (err) console.log(err);
    try {
        setupAuthTable();
        console.log("Server listening on port", PORT);
    } catch(e) {
        console.log("Error encountered on server startup", e);
    }
});
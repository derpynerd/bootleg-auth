// Project objective - 
// APIs for storing username/password combinations and authentication

const express = require('express');
const { isAuthorized, storeNewUser, setupAuthTable, getApiKeyForUser } = require('./util/helper');

const PORT = 3000;

const app = express();
app.use(express.json()); // json support 
app.use(express.urlencoded({ extended: true })) // urlencoded support


app.post('/store', async (req, res) => {
    if (req.get('Content-Type') != "application/x-www-form-urlencoded") {
        return res.status(406).json({ error: "Request format incorrect, please use Content-Type: application/x-www-form-urlencoded" });
    }

    const username = req.body.username;
    const password = req.body.password;

    console.log("Received request to store user:", username);
    const error_message = await storeNewUser(username, password);
    if (error_message != null) {
        return res.status(400).json({ message: error_message });
    }

    return res.status(201).json({ message: `Created user: ${username}` });
});

app.post('/key', async (req, res) => {
    if (req.get('Content-Type') != "application/x-www-form-urlencoded") {
        return res.status(406).json({ error: "Request format incorrect, please use Content-Type: application/x-www-form-urlencoded" });
    }

    const username = req.body.username;
    const password = req.body.password;

    console.log("Received request to authorize user:", username);
    const error_message = await isAuthorized(username, password);
    if (error_message != null) {
        return res.status(401).json({ error: error_message });
    } 

    const user_api_key = await getApiKeyForUser(username);
    return res.status(202).json({ api_key: user_api_key });
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
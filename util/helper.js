const bcrypt = require('bcrypt');
const { getClient } = require('./get-client');

module.exports = { isAuthorized, storeNewUser, setupAuthTable }

async function isAuthorized(username, password) {
    if (username == null || password == null) {
        return "null/empty username or password";
    }

    const client = await getClient();
    if (!(await doesUserExist(client, username))) {
        await client.end();
        return `User ${username} doesn't exist`;
    }

    const stored_hash = await client.query(`SELECT pass_hash FROM auth_store WHERE username = $1`, [`${username}`]);
    await client.end();

    if (!(await bcrypt.compare(password, stored_hash.rows[0].pass_hash))) {
        return `Invalid credentials`;
    }

    return null;
}

async function storeNewUser(username, password) {
    if (username == null || password == null ) {
        return "NULL username or password not allowed";
    }

    const salt_rounds = 10;
    const pass_hash = (await bcrypt.hash(password, salt_rounds)).toString();

    const client = await getClient();

    if (await doesUserExist(client, username)) {
        await client.end();
        return `User ${username} already exists`;
    }

    await client.query('INSERT INTO auth_store(username, pass_hash) VALUES($1, $2);', [`${username}`, `${pass_hash}`]);
    await client.end();

    console.info(`Stored user ${username} in database`);
    return null;
}

async function doesUserExist(client, username) {
    const user_count = await client.query(`SELECT COUNT(username) FROM auth_store WHERE username = $1`, [`${username}`]);

    if (user_count.rows[0].count == 0) return false;
    return true; 
}

async function setupAuthTable() {
    const client = await getClient();
    let create_auth_table_query = `
        CREATE TABLE IF NOT EXISTS auth_store(
        username VARCHAR PRIMARY KEY, 
        pass_hash VARCHAR NOT NULL, 
        create_time TIMESTAMP NOT NULL DEFAULT current_timestamp
        );
    `;

    await client.query(create_auth_table_query);
    await client.end();
    return;
}

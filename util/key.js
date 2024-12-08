require('dotenv').config();
  
module.exports = { generateKey, decryptKey };

async function generateKey(username) {
    // Base64 encode 'username:' + padding
    let str = btoa(username.concat(":").padEnd(25, "u&3nnv0-323n,200su32")); // TODO: Improve this

    // Encode str to UintArray8 format to perform encrypt()
    const encoder = new TextEncoder();
    const encodedStr = encoder.encode(str);
    
    // Init Vector for AES-CTR (must be 16 bytes) -- Generate during encryption and store for decryption purpose
    let iv = crypto.getRandomValues(new Uint8Array(16));

    const encrypted_content = await crypto.subtle.encrypt(
        {
        name: "AES-CTR",
        counter: iv,
        length: 128,
        },
        await getKeyMaterial(),
        encodedStr
    );

    let encrypted_key = arrayBufferToBase64(encrypted_content);
    console.log("Encrypted API Key (Base64):", encrypted_key);
    return { encrypted_key, iv };
}

async function decryptKey(encrypted_key, iv) {

    // Convert back to ArrayBuffer to perform decrypt()
    let encryptedBuffer = base64ToArrayBuffer(encrypted_key); 
    
    const decryptedContent = await crypto.subtle.decrypt(
        {
          name: "AES-CTR",
          counter: iv,
          length: 128,
        },
        await getKeyMaterial(),
        encryptedBuffer
      );

    // Decode decryptedContent into string format
    let decoder = new TextDecoder();
    let decryptedString = decoder.decode(decryptedContent);

    return atob(decryptedString).split(':').at(0);
}

async function getKeyMaterial() {
    return await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(process.env.KM_KEY), // Secret key
        { name: "AES-CTR" },
        false,
        ["encrypt", "decrypt"]
    );
}

// Convert ArrayBuffer to base64
function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }

    return btoa(binary);
}

// Convert base64 back to ArrayBuffer
function base64ToArrayBuffer(base64) {
    const binary_string = atob(base64);
    const length = binary_string.length;
    const bytes = new Uint8Array(length);
    for (let i = 0; i < length; i++) {
      bytes[i] = binary_string.charCodeAt(i);
    }

    return bytes.buffer;
}
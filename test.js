const { encrypt, decrypt } = require('./script');

const payload = {
  username: 'john_doe',
  role: 'admin'
};

// Encrypt
const encryptedToken = encrypt(payload);
console.log('🔐 Encrypted Token:', encryptedToken);

// Decrypt
const decryptedPayload = decrypt(encryptedToken);
console.log('✅ Decrypted Payload:', decryptedPayload);

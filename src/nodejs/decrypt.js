/*!
 * securfile <https://github.com/Oskang09/securfile>
 *
 * Copyright (c) 2024, Oskang09.
 * Released under the MIT License.
 * 
 * Version 0.0.1
 */

const fs = require('fs').promises; // Using fs.promises for promise-based file operations
const crypto = require('crypto');

class Securfile {
  // Decrypt a string using the provided cipher key and auth key
  static async decryptString(cipherValue, cipherKey, authKey) {
    const ciphers = cipherValue.split(',');
    if (ciphers.length !== 2) {
      throw new Error("securfile: invalid encrypted value");
    }
    return this.decrypt(ciphers[1], ciphers[0], cipherKey, authKey);
  }

  // Decrypt a file from the file system using the provided cipher key and auth key
  static async decryptFile(filePath, cipherKey, authKey) {
    const fileContent = await fs.readFile(filePath, 'utf8');
    return this.decryptString(fileContent, cipherKey, authKey);
  }

  // Decrypt a stream of a file using the provided cipher key and auth key
  static async decryptFileFromStream(fileStream, cipherKey, authKey) {
    let cipherValue = '';
    for await (const chunk of fileStream) {
      cipherValue += chunk;
    }
    return this.decryptString(cipherValue, cipherKey, authKey);
  }

  // Helper method to decrypt the actual cipher using AES-GCM
  static decrypt(cipherValue, nonceKey, cipherKey, authKey) {
    const combined = Buffer.from(cipherValue, 'base64');

    const nonce = Buffer.from(nonceKey, 'utf8');
    const tag = combined.slice(-16);
    const ciphertext = combined.slice(0, -16);

    const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(cipherKey, 'utf8'), nonce);
    decipher.setAuthTag(tag);

    let decryptedBytes;
    if (authKey) {
      decryptedBytes = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      const authBytes = Buffer.from(authKey, 'utf8');
      // Use the authBytes as additional authenticated data (AAD)
      decipher.setAAD(authBytes);
    } else {
      decryptedBytes = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    }

    return decryptedBytes.toString('utf8');
  }
}

module.exports = Securfile;

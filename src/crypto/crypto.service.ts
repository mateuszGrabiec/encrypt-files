import { Injectable } from '@nestjs/common';
import * as crypto from 'crypto';

export type KeyPair = {
  privKey: string;
  pubKey: string;
};

@Injectable()
export class CryptoService {
  generateKeyPair(): KeyPair {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem',
      },
      privateKeyEncoding: {
        type: 'pkcs1',
        format: 'pem',
        cipher: 'aes-256-cbc',
        passphrase: 'top secret',
      },
    });

    return {
      privKey: privateKey,
      pubKey: publicKey,
    };
  }

  encrypt(data: string, publicKey: string): string {
    const encryptedData = crypto.publicEncrypt(
      {
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      Buffer.from(data, 'base64'),
    );
    return encryptedData.toString('base64');
  }

  decrypt(encryptedData: string, privateKey: string) {
    return crypto.privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
        passphrase: 'top secret',
      },
      Buffer.from(encryptedData, 'base64'),
    );
  }

  encryptFile(file: Buffer, publicKey: string, privateKey: string): any {
    const message = file.toString('base64');

    const randomno = 'SwAW1D8kbcXVrq31SwAW1D8kbcXVrq31'; //Randomly generated string of length 16.
    const encryptedKey = this.encrypt(randomno, publicKey);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-ctr', randomno, iv);
    let encryptedData = cipher.update(message, 'utf8', 'base64');
    encryptedData += cipher.final('base64');

    const decryptedKey = this.decrypt(encryptedKey, privateKey).toString(
      'base64',
    );

    const decipher = crypto.createDecipheriv('aes-256-ctr', decryptedKey, iv);
    const decryptedBuffers = [
      decipher.update(Buffer.from(encryptedData, 'base64')),
    ];
    decryptedBuffers.push(decipher.final());
    const decrypted = Buffer.concat(decryptedBuffers).toString('utf8');

    console.log('is decrypted OK?', decrypted == message);

    return {
      iv: iv.toString('base64'),
      encryptedKey: encryptedKey,
      encryptedData: encryptedData,
    };
  }
}

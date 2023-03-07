import { generateKeyPair } from 'node:crypto';
import { fileURLToPath } from 'node:url';

import { promisify } from 'node:util';
import fs from 'node:fs/promises';
import path from 'node:path';

//const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(fileURLToPath(import.meta.url));

const certificatesPath = path.resolve(__dirname, 'tmp', 'certificates');

const generateKeyPairAsync = promisify(generateKeyPair);

async function generateRSAPairKeys() {
  const passphraseBuffer = await fs.readFile(
    path.resolve(__dirname, 'tmp', 'passphrase.txt')
  );

  const { publicKey, privateKey } = await generateKeyPairAsync('rsa', {
    modulusLength: 3072, // 4096
    publicExponent: 0x10001,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem',
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
      cipher: 'aes-256-cbc',
      passphrase: passphraseBuffer.toString(), // utf-8
    },
  });

  await fs.writeFile(
    path.join(certificatesPath, 'access-token-public.pem'),
    publicKey
  );

  await fs.writeFile(
    path.join(certificatesPath, 'access-token-private.pem'),
    privateKey
  );
}

void generateRSAPairKeys();

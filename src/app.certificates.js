import process from 'node:process';
import path from 'node:path';
import fs from 'node:fs';

const CERTS_PATH = path.resolve(process.cwd(), 'tmp', 'certificates');

const PRIVATE_KEY = fs.readFileSync(path.join(CERTS_PATH, 'private.pem'));

const PUBLIC_KEY = fs.readFileSync(path.join(CERTS_PATH, 'public.pem'));

export { PRIVATE_KEY, PUBLIC_KEY };

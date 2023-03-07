import { createServer } from 'node:http';
import { app } from './app.js';

const Server = createServer(app);

async function main() {
  Server.listen(3333, () => {
    console.log('\nHOST: http://localhost:3333/\nPORT: 3333');
  });
}

void main();

import mongoose from 'mongoose';
import { spawn, ChildProcess } from 'child_process';
import fs from 'fs';
import path from 'path';
import net from 'net';

let mongodProcess: ChildProcess | null = null;

function checkPortListening(port: number, host = '127.0.0.1'): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(1200);
    socket.on('connect', () => {
      socket.destroy();
      resolve(true);
    });
    socket.on('timeout', () => {
      socket.destroy();
      resolve(false);
    });
    socket.on('error', () => {
      socket.destroy();
      resolve(false);
    });
    socket.connect(port, host);
  });
}

export async function connectDatabase(): Promise<void> {
  const mongoUri = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/udyam_one';

  const isListening = await checkPortListening(27017);
  if (!isListening) {
    const defaultMongodPath = 'C:\\Program Files\\MongoDB\\Server\\8.3\\bin\\mongod.exe';
    if (fs.existsSync(defaultMongodPath)) {
      const dbPath = path.resolve(__dirname, '../../../.mongodb-data');
      if (!fs.existsSync(dbPath)) {
        fs.mkdirSync(dbPath, { recursive: true });
      }
      console.log(`[DB] Starting local MongoDB 8.3 daemon with dbpath: ${dbPath}`);
      mongodProcess = spawn(defaultMongodPath, ['--dbpath', dbPath, '--port', '27017', '--bind_ip', '127.0.0.1'], {
        stdio: 'ignore',
        detached: true,
      });
      mongodProcess.unref();

      // Wait up to 8 seconds for port 27017 to accept connections
      for (let i = 0; i < 16; i++) {
        await new Promise((r) => setTimeout(r, 500));
        if (await checkPortListening(27017)) {
          break;
        }
      }
    }
  }

  try {
    await mongoose.connect(mongoUri);
    console.log(`[DB] Connected to MongoDB: ${mongoUri}`);
  } catch (err: any) {
    if (err.message && err.message.includes('ECONNREFUSED')) {
      console.error('\n================================================================');
      console.error('❌ MONGODB CONNECTION FAILED: Port 27017 is not responding.');
      console.error('================================================================');
      console.error('The backend could not reach a running MongoDB server at 127.0.0.1:27017.');
      console.error('\nQuick fixes:');
      console.error('1. Install MongoDB Community Server on Windows:');
      console.error('   Run in PowerShell: winget install MongoDB.Server');
      console.error('   (Or download from: https://www.mongodb.com/try/download/community)');
      console.error('\n2. Or use a free cloud database (MongoDB Atlas):');
      console.error('   Set MONGODB_URI in backend/.env to your connection string:');
      console.error('   MONGODB_URI=mongodb+srv://<user>:<password>@cluster0.xxx.mongodb.net/udyam_one\n');
      console.error('================================================================\n');
    }
    throw err;
  }
}

export async function disconnectDatabase(): Promise<void> {
  await mongoose.disconnect();
}

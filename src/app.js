import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { promisify } from 'node:util';
import process from 'node:process';

import 'dotenv/config';

import compression from 'compression';
import express from 'express';

import helmet from 'helmet';
import cors from 'cors';

import timer from 'response-time';
import morgan from 'morgan';

import { UnauthorizedError, expressjwt } from 'express-jwt';
import { StatusCodes } from 'http-status-codes';

import Storage from 'node-cache';

import jsonwebtoken from 'jsonwebtoken';
import axios from 'axios';

// prettier-ignore
import { 
  PRIVATE_KEY, 
  PUBLIC_KEY 
} from './app.certificates.js';

import pkg from '../package.json' assert { type: 'json' };

assert.ok(pkg?.version);

const sign = promisify(jsonwebtoken.sign);

const blacklist = new Storage();

const api = axios.create({
  baseURL: 'https://jsonplaceholder.typicode.com',
});

export const app = express();

app.use(compression());

app.use(express.json());

app.use(helmet());
app.use(cors());

app.use(timer());
app.use(morgan('dev'));

const isUnauthorizedError = (error) => error instanceof UnauthorizedError;

const blacklistKey = (userId, sessionId) => {
  const preffix = '@BL';

  // Simple hash (testing)
  const credentials = crypto
    .createHash('md5')
    .update(`${userId}_${sessionId}`)
    .digest('hex');

  return `${preffix}:${credentials}`;
};

const mapperSession = (session) => ({
  userId: session.sub,
  sessionId: session.sid,
  tokenVersion: session.jti,
  expires: session.exp,
});

const createAuthenticatedSession = () => {
  const session = expressjwt({
    algorithms: ['RS256'],
    credentialsRequired: true,
    requestProperty: 'session',
    secret: async () => {
      return {
        key: PUBLIC_KEY,
        passphrase: process.env.PASSPHRASE,
      };
    },
    isRevoked: async (request, token) => {
      const { userId, sessionId, tokenVersion } = mapperSession(token.payload);

      const tokenVersionBlacklisted = blacklist.get(
        blacklistKey(userId, sessionId)
      );

      return tokenVersionBlacklisted
        ? tokenVersionBlacklisted === tokenVersion
        : false;
    },
  });

  return () => session;
};

const createSessionMappper = () => {
  const middleware = async (request, response, next) => {
    const rawSession = request.session; // { sid, sub, jit,... }

    try {
      const session = mapperSession(rawSession);

      request.rawSession = rawSession;
      request.session = session;

      return next();
    } catch (error) {
      return next(error);
    }
  };

  return () => middleware;
};

const useSession = createAuthenticatedSession();

const useMap = createSessionMappper();

app.get('/', (_request, response, next) => {
  const { version } = pkg;

  try {
    return response.status(StatusCodes.OK).json({ version });
  } catch (error) {
    return next(error);
  }
});

app.get('/users', useSession(), async (request, response, next) => {
  //const { username = 'lucasbernardol' } = request.query;
  try {
    const { data } = await api.get(`/users`);

    return response.status(StatusCodes.OK).json(data);
  } catch (error) {
    return next(error);
  }
});

app.post('/users/sign-in', async (_request, response, next) => {
  // Authentication/flow...
  try {
    const token = await sign(
      {
        sid: crypto.randomUUID(),
      },
      {
        key: PRIVATE_KEY,
        passphrase: process.env.PASSPHRASE,
      },
      {
        algorithm: 'RS256',
        expiresIn: '10min',
        subject: crypto.randomUUID(), // user ID
        jwtid: crypto.randomUUID(), // token/version ID
      }
    );

    return response.status(StatusCodes.OK).json({ token });
  } catch (error) {
    return next(error);
  }
});

app.get('/sessions/blacklisted', async (_request, response, next) => {
  try {
    const blacklistTuples = blacklist.keys().map((k) => [k, blacklist.get(k)]);

    return response.status(StatusCodes.OK).json(blacklistTuples);
  } catch (error) {
    return next(error);
  }
});

app.patch(
  '/sessions/logout',
  useSession(),
  useMap(),
  async (request, response, next) => {
    const { userId, sessionId, tokenVersion, expires } = request.session; // Props

    try {
      const currentTimestampUnix = Math.floor(Date.now() / 1000);

      const blacklistExpiresDiff = expires - currentTimestampUnix; // Seconds

      const currentSessionBlacklistKey = blacklistKey(userId, sessionId);

      /* key, value, expires */
      blacklist.set(
        currentSessionBlacklistKey,
        tokenVersion,
        blacklistExpiresDiff
      );

      return response.status(StatusCodes.NO_CONTENT).end();
    } catch (error) {
      return next(error);
    }
  }
);

app.use((error, _request, response, _) => {
  console.error(error);

  const isExpressJwtUnauthorizedError = isUnauthorizedError(error);

  if (isExpressJwtUnauthorizedError) {
    /** @type {UnauthorizedError} */
    const { message } = error;

    return response.status(StatusCodes.UNAUTHORIZED).json({ message });
  }

  return response.status(StatusCodes.INTERNAL_SERVER_ERROR).end();
});

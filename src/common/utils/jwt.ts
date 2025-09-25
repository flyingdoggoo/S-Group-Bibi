import jwt, { SignOptions } from 'jsonwebtoken';
import { appEnv } from '@/configs';

export interface JwtPayloadBase {
  sub: string; // user id
  type: 'access' | 'refresh';
}

export interface AccessTokenPayload extends JwtPayloadBase {
  type: 'access';
}

export interface RefreshTokenPayload extends JwtPayloadBase {
  type: 'refresh';
  tokenId: string; // for rotation or future multi-device id
}

const accessSecret = appEnv.JWT_ACCESS_SECRET;
const refreshSecret = appEnv.JWT_REFRESH_SECRET;

export function signAccessToken(userId: string) {
  const payload: AccessTokenPayload = { sub: userId, type: 'access' };
  const opts: SignOptions = { expiresIn: appEnv.JWT_ACCESS_EXPIRES };
  return jwt.sign(payload, accessSecret, opts);
}

export function signRefreshToken(userId: string, tokenId: string) {
  const payload: RefreshTokenPayload = { sub: userId, type: 'refresh', tokenId };
  const opts: SignOptions = { expiresIn: appEnv.JWT_REFRESH_EXPIRES };
  return jwt.sign(payload, refreshSecret, opts);
}

export function verifyAccessToken(token: string): AccessTokenPayload | null {
  try {
    const decoded = jwt.verify(token, accessSecret) as AccessTokenPayload;
    if (decoded.type !== 'access') return null;
    return decoded;
  } catch {
    return null;
  }
}

export function verifyRefreshToken(token: string): RefreshTokenPayload | null {
  try {
    const decoded = jwt.verify(token, refreshSecret) as RefreshTokenPayload;
    if (decoded.type !== 'refresh') return null;
    return decoded;
  } catch {
    return null;
  }
}

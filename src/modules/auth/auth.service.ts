import { StatusCodes } from 'http-status-codes';
import bcrypt from 'bcrypt';
import { authRepository } from './auth.repository';
import { RegisterRequest, RegisterResponse, LoginResponse } from './auth.dto';
import { ResponseStatus, ServiceResponse } from '@/common';
import { signAccessToken, signRefreshToken, verifyRefreshToken } from '@/common/utils/jwt';
import { appEnv } from '@/configs';
import crypto from 'crypto';

const SALT_ROUNDS = 10;

class AuthService {
  async register(payload: RegisterRequest) {
    const existing = await authRepository.findByEmail(payload.email);
    if (existing) {
      return new ServiceResponse(
        ResponseStatus.Failed,
        'Email đã tồn tại',
        null,
        StatusCodes.CONFLICT
      );
    }

    const passwordHash = await bcrypt.hash(payload.password, SALT_ROUNDS);
    const user = await authRepository.createUser({
      email: payload.email,
      passwordHash,
      name: payload.name,
    });

    const dto: RegisterResponse = {
      id: user.id,
      email: user.email,
      name: user.name ?? null,
      isEmailVerified: user.isEmailVerified,
      createdAt: user.createdAt.toISOString(),
    };

    return new ServiceResponse(
      ResponseStatus.Success,
      'Đăng ký thành công',
      dto,
      StatusCodes.CREATED
    );
  }

  private hashRefresh(raw: string) {
    return crypto.createHash('sha256').update(raw).digest('hex');
  }

  async login(email: string, password: string) {
    const user = await authRepository.findByEmail(email);
    if (!user) {
      return new ServiceResponse(ResponseStatus.Failed, 'Email hoặc mật khẩu sai', null, StatusCodes.UNAUTHORIZED);
    }
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) {
      return new ServiceResponse(ResponseStatus.Failed, 'Email hoặc mật khẩu sai', null, StatusCodes.UNAUTHORIZED);
    }

    const tokenId = crypto.randomUUID();
    const accessToken = signAccessToken(user.id);
    const refreshToken = signRefreshToken(user.id, tokenId);
    const refreshTokenHash = this.hashRefresh(refreshToken);
    await authRepository.updateRefreshToken(user.id, refreshTokenHash);

    const dto: RegisterResponse = {
      id: user.id,
      email: user.email,
      name: user.name ?? null,
      isEmailVerified: user.isEmailVerified,
      createdAt: user.createdAt.toISOString(),
    };

    const response: LoginResponse = { user: dto };
    return new ServiceResponse(ResponseStatus.Success, 'Đăng nhập thành công', { accessToken, refreshToken, ...response }, StatusCodes.OK);
  }

  async refresh(oldRefreshToken: string) {
    const decoded = verifyRefreshToken(oldRefreshToken);
    if (!decoded) {
      return new ServiceResponse(
        ResponseStatus.Failed,
        'Refresh token không hợp lệ',
        null,
        StatusCodes.UNAUTHORIZED
      );
    }
    const user = await authRepository.findById(decoded.sub);
    if (!user || !user.refreshTokenHash) {
      return new ServiceResponse(
        ResponseStatus.Failed,
        'Refresh token không hợp lệ',
        null,
        StatusCodes.UNAUTHORIZED
      );
    }
    const incomingHash = this.hashRefresh(oldRefreshToken);
    if (incomingHash !== user.refreshTokenHash) {
      // Token reuse / invalidated
      await authRepository.updateRefreshToken(user.id, null);
      return new ServiceResponse(
        ResponseStatus.Failed,
        'Refresh token không hợp lệ',
        null,
        StatusCodes.UNAUTHORIZED
      );
    }

    // Rotate
    const newTokenId = crypto.randomUUID();
    const accessToken = signAccessToken(user.id);
    const newRefreshToken = signRefreshToken(user.id, newTokenId);
    const newHash = this.hashRefresh(newRefreshToken);
    await authRepository.updateRefreshToken(user.id, newHash);

    const dto: RegisterResponse = {
      id: user.id,
      email: user.email,
      name: user.name ?? null,
      isEmailVerified: user.isEmailVerified,
      createdAt: user.createdAt.toISOString(),
    };
    const payload: LoginResponse = { user: dto };
    return new ServiceResponse(
      ResponseStatus.Success,
      'Refresh thành công',
      { accessToken, refreshToken: newRefreshToken, ...payload },
      StatusCodes.OK
    );
  }

  async logout(userId: string) {
    await authRepository.updateRefreshToken(userId, null);
    return new ServiceResponse(ResponseStatus.Success, 'Đăng xuất thành công', null, StatusCodes.OK);
  }

  // ========== GOOGLE OAUTH (simple) ==========
  buildGoogleAuthUrl(state: string) {
    const root = 'https://accounts.google.com/o/oauth2/v2/auth';
    const params = new URLSearchParams({
      client_id: appEnv.GOOGLE_CLIENT_ID,
      redirect_uri: appEnv.GOOGLE_REDIRECT_URI,
      response_type: 'code',
      scope: 'openid email profile',
      access_type: 'offline',
      prompt: 'consent',
      state,
    });
    return `${root}?${params.toString()}`;
  }

  async exchangeCodeForTokens(code: string) {
    const body = new URLSearchParams({
      code,
      client_id: appEnv.GOOGLE_CLIENT_ID,
      client_secret: appEnv.GOOGLE_CLIENT_SECRET,
      redirect_uri: appEnv.GOOGLE_REDIRECT_URI,
      grant_type: 'authorization_code',
    });
    const resp = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    });
    if (!resp.ok) throw new Error('Exchange code thất bại');
    return resp.json() as Promise<{
      access_token: string; id_token: string; expires_in: number; refresh_token?: string; scope: string; token_type: string;
    }>;
  }

  decodeIdToken(idToken: string) {
    const part = idToken.split('.')[1];
    const json = Buffer.from(part, 'base64url').toString('utf8');
    return JSON.parse(json);
  }

  async googleLogin(idToken: string) {
    const payload = this.decodeIdToken(idToken);
    // Basic validate
    if (!payload || !payload.email || !payload.sub) {
      return new ServiceResponse(ResponseStatus.Failed, 'Google token không hợp lệ', null, StatusCodes.UNAUTHORIZED);
    }
    const email = String(payload.email).toLowerCase();
    // Upsert (tạo mới nếu chưa có, update nếu đã tồn tại).
    const user = await (authRepository as any).prisma?.user?.upsert
      ? (authRepository as any).prisma.user.upsert({}) // placeholder (not used)
      : await (await import('@/prisma/client')).prisma.user.upsert({
        where: { email },
        update: {
          name: payload.name,
          avatarUrl: payload.picture,
          provider: 'GOOGLE',
          providerId: payload.sub,
          isEmailVerified: payload.email_verified ?? false,
          lastLoginAt: new Date(),
        },
        create: {
          email,
          name: payload.name,
          avatarUrl: payload.picture,
          provider: 'GOOGLE',
          providerId: payload.sub,
          isEmailVerified: payload.email_verified ?? false,
          lastLoginAt: new Date(),
        },
      });

    const tokenId = crypto.randomUUID();
    const accessToken = signAccessToken(user.id);
    const refreshToken = signRefreshToken(user.id, tokenId);
    const refreshHash = this.hashRefresh(refreshToken);
    await authRepository.updateRefreshToken(user.id, refreshHash);

    const dto: RegisterResponse = {
      id: user.id,
      email: user.email,
      name: user.name ?? null,
      isEmailVerified: user.isEmailVerified,
      createdAt: user.createdAt.toISOString(),
    };

    return new ServiceResponse(
      ResponseStatus.Success,
      'Đăng nhập Google thành công',
      { accessToken, refreshToken, user: dto },
      StatusCodes.OK
    );
  }
}

export const authService = new AuthService();

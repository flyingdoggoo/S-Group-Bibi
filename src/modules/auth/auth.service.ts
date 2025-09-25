import { StatusCodes } from 'http-status-codes';
import bcrypt from 'bcrypt';
import { authRepository } from './auth.repository';
import { RegisterRequest, RegisterResponse } from './auth.dto';
import { ResponseStatus, ServiceResponse } from '@/common';

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
}

export const authService = new AuthService();

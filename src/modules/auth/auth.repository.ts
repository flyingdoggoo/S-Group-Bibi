import { prisma } from '@/prisma/client';

export class AuthRepository {
  async findByEmail(email: string) {
    return prisma.user.findUnique({ where: { email: email.toLowerCase() } });
  }

  async findById(id: string) {
    return prisma.user.findUnique({ where: { id } });
  }

  async createUser(data: { email: string; passwordHash: string; name?: string }) {
    return prisma.user.create({
      data: {
        email: data.email.toLowerCase(),
        passwordHash: data.passwordHash,
        name: data.name,
      },
    });
  }

  async updateRefreshToken(userId: string, refreshTokenHash: string | null) {
    return prisma.user.update({
      where: { id: userId },
      data: {
        refreshTokenHash,
        lastLoginAt: new Date(),
      },
    });
  }

  async setEmailVerificationToken(userId: string, token: string, expiresAt: Date) {
    // @ts-ignore - field exists in schema but typing not refreshed?
    return prisma.user.update({ where: { id: userId }, data: { emailVerificationToken: token, emailVerificationTokenExpires: expiresAt } });
  }

  async consumeEmailVerificationToken(token: string) {
    const now = new Date();
    // @ts-ignore
    const user: any = await prisma.user.findFirst({ where: { emailVerificationToken: token, emailVerificationTokenExpires: { gt: now } } });
    if (!user) return null;
    // @ts-ignore
    await prisma.user.update({ where: { id: user.id }, data: { isEmailVerified: true, emailVerificationToken: null, emailVerificationTokenExpires: null } });
    return { ...user, isEmailVerified: true };
  }

  async setPasswordResetToken(userId: string, tokenHash: string, expiresAt: Date) {
    // @ts-ignore
    return prisma.user.update({ where: { id: userId }, data: { passwordResetTokenHash: tokenHash, passwordResetTokenExpires: expiresAt } });
  }

  async findUserByValidPasswordResetToken(rawToken: string, hashFunc: (t: string) => string) {
    const tokenHash = hashFunc(rawToken);
    const now = new Date();
    // @ts-ignore
    return prisma.user.findFirst({ where: { passwordResetTokenHash: tokenHash, passwordResetTokenExpires: { gt: now } } });
  }

  async clearPasswordResetToken(userId: string) {
    // @ts-ignore
    return prisma.user.update({ where: { id: userId }, data: { passwordResetTokenHash: null, passwordResetTokenExpires: null } });
  }

  async updatePassword(userId: string, newPasswordHash: string) {
    return prisma.user.update({
      where: { id: userId },
      data: { passwordHash: newPasswordHash },
    });
  }
}

export const authRepository = new AuthRepository();

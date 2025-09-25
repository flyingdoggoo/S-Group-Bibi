import { z } from 'zod';
// Dùng zod để tạo ra schema (khuôn mẫu dữ liệu) và validate dữ liệu.
export const UserDtoSchema = z.object({
  id: z.string(),
  email: z.string().email(),
  name: z.string().nullable().optional(),
  isEmailVerified: z.boolean(),
  createdAt: z.string(),
});

export type UserDto = z.infer<typeof UserDtoSchema>;

export const RegisterRequestSchema = z
  .object({
    email: z.string().email('Email không hợp lệ'),
    password: z
      .string()
      .min(8, 'Tối thiểu 8 ký tự')
      .regex(/[A-Z]/, 'Cần ít nhất 1 chữ hoa'),
    confirmPassword: z.string(),
    name: z.string().min(1).max(120).optional(),
  })
  .refine((d) => d.password === d.confirmPassword, {
    message: 'Mật khẩu xác nhận không khớp',
    path: ['confirmPassword'],
  });

export const LoginRequestSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1)
});


export type RegisterRequest = z.infer<typeof RegisterRequestSchema>;
export const RegisterResponseSchema = UserDtoSchema; // hoặc null nếu chỉ trả message
export type RegisterResponse = z.infer<typeof RegisterResponseSchema>;
export type LoginRequest = z.infer<typeof LoginRequestSchema>;
export const LoginResponseSchema = z.object({
  user: UserDtoSchema,
});
export type LoginResponse = z.infer<typeof LoginResponseSchema>;

// Email verification DTOs
export const RequestEmailVerificationSchema = z.object({
  email: z.string().email(),
});
export type RequestEmailVerification = z.infer<typeof RequestEmailVerificationSchema>;

export const VerifyEmailSchema = z.object({
  token: z.string().min(10),
});
export type VerifyEmailRequest = z.infer<typeof VerifyEmailSchema>;

// ========== Password Reset & Change DTOs ==========
export const ForgotPasswordRequestSchema = z.object({
  email: z.string().email(),
});
export type ForgotPasswordRequest = z.infer<typeof ForgotPasswordRequestSchema>;

export const ResetPasswordRequestSchema = z
  .object({
    token: z.string().min(20),
    newPassword: z
      .string()
      .min(8, 'Tối thiểu 8 ký tự')
      .regex(/[A-Z]/, 'Cần ít nhất 1 chữ hoa'),
    confirmNewPassword: z.string(),
  })
  .refine((d) => d.newPassword === d.confirmNewPassword, {
    message: 'Mật khẩu xác nhận không khớp',
    path: ['confirmNewPassword'],
  });
export type ResetPasswordRequest = z.infer<typeof ResetPasswordRequestSchema>;

export const ChangePasswordRequestSchema = z
  .object({
    userId: z.string().uuid(), // Tạm thời truyền userId, sau này lấy từ accessToken
    currentPassword: z.string().min(1),
    newPassword: z
      .string()
      .min(8, 'Tối thiểu 8 ký tự')
      .regex(/[A-Z]/, 'Cần ít nhất 1 chữ hoa'),
    confirmNewPassword: z.string(),
  })
  .refine((d) => d.newPassword === d.confirmNewPassword, {
    message: 'Mật khẩu xác nhận không khớp',
    path: ['confirmNewPassword'],
  });
export type ChangePasswordRequest = z.infer<typeof ChangePasswordRequestSchema>;

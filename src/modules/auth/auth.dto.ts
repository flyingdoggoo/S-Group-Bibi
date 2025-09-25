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
  
export type RegisterRequest = z.infer<typeof RegisterRequestSchema>;

export const RegisterResponseSchema = UserDtoSchema; // hoặc null nếu chỉ trả message

export type RegisterResponse = z.infer<typeof RegisterResponseSchema>;

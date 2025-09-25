import express, { Request, Response, Router } from 'express';
import { OpenAPIRegistry, extendZodWithOpenApi } from '@asteasolutions/zod-to-openapi';
import { StatusCodes } from 'http-status-codes';
import { RegisterRequestSchema, RegisterResponseSchema } from './auth.dto';
import { authService } from './auth.service';
import { ServiceResponse, ResponseStatus } from '@/common';
import { createApiResponse } from '@/swagger/openAPIResponseBuilders';
import { z } from 'zod';
// express → framework backend (dùng để tạo API).
// zod → thư viện validate dữ liệu (check email hợp lệ, mật khẩu ≥ 8 ký tự…).
// @asteasolutions/zod-to-openapi → dùng để chuyển schema của Zod thành tài liệu Swagger/OpenAPI.
// http-status-codes → thay vì nhớ số 400, 401, 201, … thì dùng StatusCodes.BAD_REQUEST cho rõ nghĩa.
// ServiceResponse, ResponseStatus → cấu trúc chuẩn để trả về dữ liệu (do bạn hoặc team định nghĩa trong @/common).
// createApiResponse → helper để định nghĩa response cho Swagger.

// Đảm bảo mở rộng Zod trước khi đăng ký schema
extendZodWithOpenApi(z);

export const authRegistry = new OpenAPIRegistry();

// 👉 Đây là chỗ đăng ký schema với Swagger để tự sinh tài liệu API.
authRegistry.register('RegisterRequest', RegisterRequestSchema);
authRegistry.register('RegisterResponse', RegisterResponseSchema);

authRegistry.registerPath({
  method: 'post',
  path: '/auth/register',
  tags: ['Auth'],
  request: {
    body: {
      content: {
        'application/json': { schema: RegisterRequestSchema },
      },
    },
  },
  responses: {
    ...createApiResponse(RegisterResponseSchema, 'Đăng ký thành công', StatusCodes.CREATED),
    //Request body phải theo RegisterRequestSchema (email, password, confirmPassword).
    ...createApiResponse(z.null(), 'Email đã tồn tại', StatusCodes.CONFLICT),
    ...createApiResponse(z.null(), 'Dữ liệu không hợp lệ', StatusCodes.BAD_REQUEST),
  },
});

export const authRouter: Router = (() => {
  const router = express.Router();

  router.post('/register', async (req: Request, res: Response) => {
    const parsed = RegisterRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(StatusCodes.BAD_REQUEST).json(
        new ServiceResponse(
          ResponseStatus.Failed,
          'Dữ liệu không hợp lệ',
          { errors: parsed.error.flatten() },
          StatusCodes.BAD_REQUEST
        )
      );
    }
    const serviceResponse = await authService.register(parsed.data);
    return res.status(serviceResponse.code).json(serviceResponse);
  });

  return router;
})();

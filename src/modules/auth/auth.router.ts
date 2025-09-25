import express, { Request, Response, Router } from 'express';
import { OpenAPIRegistry, extendZodWithOpenApi } from '@asteasolutions/zod-to-openapi';
import { StatusCodes } from 'http-status-codes';
import { RegisterRequestSchema, RegisterResponseSchema, LoginResponseSchema, LoginRequestSchema } from './auth.dto';
import { authService } from './auth.service';
import { ServiceResponse, ResponseStatus } from '@/common';
import { createApiResponse } from '@/swagger/openAPIResponseBuilders';
import { z } from 'zod';
import crypto from 'crypto';
import { appEnv } from '@/configs';
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
authRegistry.register('LoginRequest', LoginRequestSchema);
authRegistry.register('LoginResponse', LoginResponseSchema);

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
// Google OAuth paths (simple)
authRegistry.registerPath({
  method: 'get',
  path: '/auth/google',
  tags: ['Auth'],
  responses: {
    302: { description: 'Redirect tới Google OAuth consent screen' },
  },
});
authRegistry.registerPath({
  method: 'get',
  path: '/auth/google/callback',
  tags: ['Auth'],
  parameters: [
    { name: 'code', in: 'query', required: true, schema: { type: 'string' } },
    { name: 'state', in: 'query', required: false, schema: { type: 'string' } },
  ],
  responses: {
    302: { description: 'Đăng nhập thành công -> redirect FRONTEND_URL' },
    400: { description: 'Thiếu code hoặc lỗi' },
    500: { description: 'Lỗi server' },
  },
});
authRegistry.registerPath({
  method: 'post',
  path: '/auth/login',
  tags: ['Auth'],
  request: {
    body: {
      content: {
        'application/json': { schema: LoginRequestSchema },
      },
    },
  },
  responses: {
    ...createApiResponse(LoginResponseSchema, 'Đăng nhập thành công', StatusCodes.OK),
    //Request body phải theo LoginRequestSchema (email, password).
    ...createApiResponse(z.null(), 'Email hoặc mật khẩu sai', StatusCodes.UNAUTHORIZED),
    ...createApiResponse(z.null(), 'Dữ liệu không hợp lệ', StatusCodes.BAD_REQUEST),
  },
});
authRegistry.registerPath({
  method: 'post',
  path: '/auth/refresh',
  tags: ['Auth'],
  responses: {
    200: { description: 'Cấp lại access token thành công (rotate refresh)' },
    401: { description: 'Refresh token không hợp lệ' },
  },
});
authRegistry.registerPath({
  method: 'post',
  path: '/auth/logout',
  tags: ['Auth'],
  responses: {
    200: { description: 'Đăng xuất thành công' },
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
  router.post('/login', async (req: Request, res: Response) => {
    const parsed = LoginRequestSchema.safeParse(req.body);
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

    const serviceResponse = await authService.login(parsed.data.email, parsed.data.password);
    return res.status(serviceResponse.code).json(serviceResponse);
  });

  router.post('/refresh', async (req: Request, res: Response) => {
    const refreshToken = req.cookies?.refreshToken || req.body?.refreshToken;
    if (!refreshToken) {
      return res.status(StatusCodes.UNAUTHORIZED).json(new ServiceResponse(
        ResponseStatus.Failed,
        'Thiếu refresh token',
        null,
        StatusCodes.UNAUTHORIZED
      ));
    }
    const serviceResp = await authService.refresh(refreshToken);
    if (serviceResp.code !== StatusCodes.OK) {
      return res.status(serviceResp.code).json(serviceResp);
    }
    const data: any = serviceResp.data;
    const common = {
      httpOnly: true,
      secure: appEnv.COOKIE_SECURE,
      sameSite: appEnv.COOKIE_SAME_SITE as any,
      domain: appEnv.COOKIE_DOMAIN || undefined,
      path: '/',
    };
    res.cookie('accessToken', data.accessToken, { ...common, maxAge: appEnv.JWT_ACCESS_EXPIRES * 1000 });
    res.cookie('refreshToken', data.refreshToken, { ...common, maxAge: appEnv.JWT_REFRESH_EXPIRES * 1000 });
    return res.status(serviceResp.code).json(serviceResp);
  });

  router.post('/logout', async (req: Request, res: Response) => {
    // Đơn giản: cần userId -> ở đây chưa có middleware decode accessToken nên tạm lấy từ body
    const { userId } = req.body || {};
    if (!userId) {
      return res.status(StatusCodes.BAD_REQUEST).json(new ServiceResponse(
        ResponseStatus.Failed,
        'Thiếu userId',
        null,
        StatusCodes.BAD_REQUEST
      ));
    }
    const serviceResp = await authService.logout(userId);
    const clearOpts: any = {
      httpOnly: true,
      secure: appEnv.COOKIE_SECURE,
      sameSite: appEnv.COOKIE_SAME_SITE as any,
      domain: appEnv.COOKIE_DOMAIN || undefined,
      path: '/',
    };
    res.clearCookie('accessToken', clearOpts);
    res.clearCookie('refreshToken', clearOpts);
    return res.status(serviceResp.code).json(serviceResp);
  });

  // In-memory state store (simple). Production: Redis.
  const oauthStateStore = new Map<string, number>();

  router.get('/google', (req: Request, res: Response) => {
    const state = crypto.randomUUID();
    oauthStateStore.set(state, Date.now() + 5 * 60 * 1000); // 5 minutes ttl
    const url = authService.buildGoogleAuthUrl(state);
    return res.redirect(url);
  });

  router.get('/google/callback', async (req: Request, res: Response) => {
    const { code, state } = req.query;
    if (!code) {
      return res.status(StatusCodes.BAD_REQUEST).send('Missing code');
    }
    if (state && (!oauthStateStore.has(String(state)) || (oauthStateStore.get(String(state)) || 0) < Date.now())) {
      return res.status(StatusCodes.BAD_REQUEST).send('Invalid state');
    }
    if (state) oauthStateStore.delete(String(state));
    try {
      const tokens = await authService.exchangeCodeForTokens(String(code));
      const serviceResp = await authService.googleLogin(tokens.id_token);
      if (serviceResp.code !== StatusCodes.OK) {
        return res.status(serviceResp.code).json(serviceResp);
      }
      const data: any = serviceResp.data;
      // Set cookies (simple)
      const common = {
        httpOnly: true,
        secure: appEnv.COOKIE_SECURE,
        sameSite: appEnv.COOKIE_SAME_SITE as any,
        domain: appEnv.COOKIE_DOMAIN || undefined,
        path: '/',
      };
      res.cookie('accessToken', data.accessToken, { ...common, maxAge: appEnv.JWT_ACCESS_EXPIRES * 1000 });
      res.cookie('refreshToken', data.refreshToken, { ...common, maxAge: appEnv.JWT_REFRESH_EXPIRES * 1000 });
      // Redirect frontend
      return res.json({
        message: 'Google login ok',
        user: data.user,
        accessToken: data.accessToken,
        refreshToken: data.refreshToken
      });
    } catch (e: any) {
      console.error(e);
      return res.status(500).send('OAuth error');
    }
  });

  return router;
})();

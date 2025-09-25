import { extendZodWithOpenApi } from '@asteasolutions/zod-to-openapi';
import { z } from 'zod';

// Bootstrap openapi() patch for Zod BEFORE any module registers schemas.
if (!(z as any).__OPENAPI_PATCHED__) {
  extendZodWithOpenApi(z);
  (z as any).__OPENAPI_PATCHED__ = true;
  // Debug one-time
  // eslint-disable-next-line no-console
  console.log('[bootstrap] zod-to-openapi extended. openapi method available:', typeof (z.string() as any).openapi === 'function');
}

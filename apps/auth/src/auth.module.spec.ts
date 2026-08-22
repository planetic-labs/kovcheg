import { Test } from '@nestjs/testing';
import { describe, expect, it } from 'vitest';

import { AuthModule } from './auth.module.js';

describe('AuthModule', () => {
  it('compiles the auth foundation', async () => {
    const moduleRef = await Test.createTestingModule({ imports: [AuthModule] }).compile();

    expect(moduleRef.get(AuthModule)).toBeInstanceOf(AuthModule);
    await moduleRef.close();
  });
});

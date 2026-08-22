import { Test } from '@nestjs/testing';
import { describe, expect, it } from 'vitest';

import { ApiModule } from './api.module.js';

describe('ApiModule', () => {
  it('compiles the API foundation', async () => {
    const moduleRef = await Test.createTestingModule({ imports: [ApiModule.register()] }).compile();

    expect(moduleRef.get(ApiModule)).toBeInstanceOf(ApiModule);
    await moduleRef.close();
  });
});

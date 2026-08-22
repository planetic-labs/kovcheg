import { Test } from '@nestjs/testing';
import { describe, expect, it } from 'vitest';

import { WorkerModule } from './worker.module.js';

describe('WorkerModule', () => {
  it('compiles the empty worker foundation', async () => {
    const moduleRef = await Test.createTestingModule({ imports: [WorkerModule] }).compile();

    expect(moduleRef.get(WorkerModule)).toBeInstanceOf(WorkerModule);
    await moduleRef.close();
  });
});

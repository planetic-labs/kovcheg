import type { UserId, Uuid } from '@kovcheg/contracts';
import type { Pool } from 'pg';
import { describe, expect, it, vi } from 'vitest';

import { PostgresRealtimeRepository, RealtimeRepositoryError } from './realtime.repository.js';

const userId = '00000000-0000-4000-8000-000000005001' as UserId;
const chatId = '00000000-0000-4000-8000-000000005101' as Uuid;

describe('PostgresRealtimeRepository authorization', () => {
  it('rechecks active PostgreSQL membership before realtime delivery', async () => {
    const query = vi.fn().mockResolvedValue({ rows: [{ allowed: true }] });
    const repository = new PostgresRealtimeRepository({ query } as unknown as Pool);

    await expect(repository.canReadChat(userId, chatId)).resolves.toBe(true);
    expect(query).toHaveBeenCalledWith('SELECT kovcheg.can_account_read_chat($1, $2) AS allowed', [
      userId,
      chatId,
    ]);
  });

  it('uses current read capability for full catch-up without a join-period cutoff', async () => {
    const query = vi
      .fn()
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValueOnce({ rows: [{ allowed: true }] })
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValueOnce({ rows: [] });
    const release = vi.fn();
    const repository = new PostgresRealtimeRepository({
      connect: vi.fn().mockResolvedValue({ query, release }),
    } as unknown as Pool);

    await repository.subscribe({ afterSequence: '0', chatId, limit: 100, userId });
    expect(query.mock.calls[2]?.[0]).not.toContain('chat_membership_periods');
    expect(query.mock.calls[2]?.[1]).toEqual([chatId, '0', 100]);
  });

  it('fails closed when membership cannot be checked', async () => {
    const repository = new PostgresRealtimeRepository({
      query: vi.fn().mockRejectedValue(new Error('synthetic database failure')),
    } as unknown as Pool);

    await expect(repository.canReadChat(userId, chatId)).rejects.toBeInstanceOf(
      RealtimeRepositoryError,
    );
  });
});

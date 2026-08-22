import { createServiceHealth } from '@kovcheg/contracts';

export function GET(): Response {
  return Response.json(createServiceHealth('web', 'live'));
}

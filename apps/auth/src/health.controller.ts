import { createServiceHealth } from '@kovcheg/contracts';
import type { ServiceHealth } from '@kovcheg/contracts';
import { Controller, Get } from '@nestjs/common';
import { ApiOkResponse, ApiTags } from '@nestjs/swagger';
import type { SchemaObject } from '@nestjs/swagger';

const healthSchema: SchemaObject = {
  properties: {
    contractVersion: { example: 1, type: 'integer' },
    service: { example: 'auth', type: 'string' },
    state: { enum: ['live', 'ready'], type: 'string' },
    status: { example: 'ok', type: 'string' },
  },
  required: ['contractVersion', 'service', 'state', 'status'],
  type: 'object',
};

@ApiTags('health')
@Controller('health')
export class HealthController {
  @ApiOkResponse({ description: 'The auth process is running.', schema: healthSchema })
  @Get('live')
  live(): ServiceHealth {
    return createServiceHealth('auth', 'live');
  }

  @ApiOkResponse({
    description: 'The auth process is ready for local requests.',
    schema: healthSchema,
  })
  @Get('ready')
  ready(): ServiceHealth {
    return createServiceHealth('auth', 'ready');
  }
}

import { loadServiceConfig } from '@kovcheg/config';
import { createServiceHealth, serviceHealthJsonSchema } from '@kovcheg/contracts';
import type { ServiceHealth } from '@kovcheg/contracts';
import { Controller, Get } from '@nestjs/common';
import { ApiOkResponse, ApiTags } from '@nestjs/swagger';

@ApiTags('health')
@Controller('health')
export class HealthController {
  @ApiOkResponse({
    description: 'The API process is running.',
    schema: serviceHealthJsonSchema,
  })
  @Get('live')
  live(): ServiceHealth {
    return createServiceHealth('api', 'live', { build: loadServiceConfig('api').build });
  }

  @ApiOkResponse({
    description: 'The API process is ready for local requests.',
    schema: serviceHealthJsonSchema,
  })
  @Get('ready')
  ready(): ServiceHealth {
    return createServiceHealth('api', 'ready', { build: loadServiceConfig('api').build });
  }
}

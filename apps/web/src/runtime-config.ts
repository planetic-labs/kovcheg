import { loadServiceConfig } from '@kovcheg/config';
import type { EnvironmentSource, ServiceRuntimeConfig } from '@kovcheg/config';

export function loadWebRuntimeConfig(
  environment: EnvironmentSource = process.env,
): ServiceRuntimeConfig {
  return loadServiceConfig('web', environment);
}

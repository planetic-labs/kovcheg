import { loadWebRuntimeConfig } from './runtime-config';

export function register(): void {
  if (process.env.NEXT_RUNTIME === 'nodejs') {
    loadWebRuntimeConfig();
  }
}

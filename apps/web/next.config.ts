import type { NextConfig } from 'next';
import { fileURLToPath } from 'node:url';

const nextConfig: NextConfig = {
  agentRules: false,
  output: 'standalone',
  outputFileTracingRoot: fileURLToPath(new URL('../..', import.meta.url)),
  poweredByHeader: false,
  productionBrowserSourceMaps: false,
  reactStrictMode: true,
};

export default nextConfig;

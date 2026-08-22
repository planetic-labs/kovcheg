export const foundationContractVersion = 1 as const;

export type ServiceName = 'api' | 'auth' | 'web' | 'worker';

export interface ServiceDescriptor {
  readonly contractVersion: typeof foundationContractVersion;
  readonly name: ServiceName;
}

export type Uuid = `${string}-${string}-${string}-${string}-${string}`;
export type UserId = Uuid;
export type SessionId = Uuid;

declare const correlationIdBrand: unique symbol;
export type CorrelationId = string & { readonly [correlationIdBrand]: true };

import {
  chatListContractVersion,
  domainStatuses,
  functionalGrants,
  messageFlowContractVersion,
  messageHistoryContractVersion,
  parseCurrentPrincipalAuthorization,
  realtimeContractVersion,
} from '@kovcheg/contracts';
import type {
  AvailableChat,
  CreateTextMessageResponse,
  CurrentPrincipalAuthorization,
  DomainStatus,
  FunctionalGrant,
  MessageHistoryPage,
  RealtimeSubscribeResult,
  TextMessage,
  UserId,
  Uuid,
} from '@kovcheg/contracts';

type AccountStatus = 'active' | 'deactivated';
export type SessionPrincipal = CurrentPrincipalAuthorization;

export interface AccountRecord {
  readonly accountAccess: 'member';
  readonly displayName: string;
  readonly domainStatus: DomainStatus;
  readonly email: string;
  readonly functionalGrants: readonly FunctionalGrant[];
  readonly status: AccountStatus;
  readonly userId: UserId;
}

export interface ChatListResponse {
  readonly contractVersion: typeof chatListContractVersion;
  readonly items: readonly AvailableChat[];
}

export interface AccountDetail extends AccountRecord {
  readonly nextAuthorizationVersion: number;
  readonly isServerOwner: boolean;
}
export type AccountListItem = Pick<AccountRecord, 'userId' | 'displayName' | 'email' | 'status'>;
export interface AccountListPage {
  readonly items: readonly AccountListItem[];
  readonly nextAfterAccountId: UserId | null;
}
export interface OwnPasskeySettings {
  readonly everAdded: boolean;
  readonly activePasskeyCount: number;
  readonly activePasskeys: readonly Readonly<{
    id: Uuid;
    createdAt: string;
    lastUsedAt: string | null;
    status: 'active';
  }>[];
}

export function parseAccountDetail(value: unknown): AccountDetail | null {
  const account = parseAccountRecord(value);
  if (
    account === null ||
    !isRecord(value) ||
    !Number.isSafeInteger(value.nextAuthorizationVersion) ||
    (value.nextAuthorizationVersion as number) < 2 ||
    typeof value.isServerOwner !== 'boolean'
  )
    return null;
  return {
    ...account,
    nextAuthorizationVersion: value.nextAuthorizationVersion as number,
    isServerOwner: value.isServerOwner,
  };
}

export function parseAccountListPage(value: unknown): AccountListPage | null {
  if (
    !isRecord(value) ||
    !Array.isArray(value.items) ||
    value.items.length > 100 ||
    (value.nextAfterAccountId !== null && !isUuid(value.nextAfterAccountId))
  )
    return null;
  const items: AccountListItem[] = [];
  for (const item of value.items) {
    if (
      !isRecord(item) ||
      !isUuid(item.userId) ||
      typeof item.displayName !== 'string' ||
      typeof item.email !== 'string' ||
      (item.status !== 'active' && item.status !== 'deactivated')
    )
      return null;
    items.push({
      userId: item.userId as UserId,
      displayName: item.displayName,
      email: item.email,
      status: item.status,
    });
  }
  if (
    new Set(items.map((item) => item.userId)).size !== items.length ||
    (value.nextAfterAccountId !== null && value.nextAfterAccountId !== items.at(-1)?.userId)
  )
    return null;
  return { items, nextAfterAccountId: value.nextAfterAccountId as UserId | null };
}

export function parseOwnPasskeySettings(value: unknown): OwnPasskeySettings | null {
  if (
    !isRecord(value) ||
    typeof value.everAdded !== 'boolean' ||
    !Number.isSafeInteger(value.activePasskeyCount) ||
    !Array.isArray(value.activePasskeys) ||
    value.activePasskeyCount !== value.activePasskeys.length ||
    (!value.everAdded && value.activePasskeyCount !== 0)
  )
    return null;
  const keys: OwnPasskeySettings['activePasskeys'][number][] = [];
  for (const key of value.activePasskeys) {
    if (
      !isRecord(key) ||
      Object.keys(key).sort().join(',') !== 'createdAt,id,lastUsedAt,status' ||
      !isUuid(key.id) ||
      key.status !== 'active' ||
      typeof key.createdAt !== 'string' ||
      !Number.isFinite(Date.parse(key.createdAt)) ||
      (key.lastUsedAt !== null &&
        (typeof key.lastUsedAt !== 'string' || !Number.isFinite(Date.parse(key.lastUsedAt))))
    )
      return null;
    keys.push({
      id: key.id,
      createdAt: key.createdAt,
      lastUsedAt: key.lastUsedAt as string | null,
      status: 'active',
    });
  }
  if (new Set(keys.map((key) => key.id)).size !== keys.length) return null;
  return { everAdded: value.everAdded, activePasskeyCount: keys.length, activePasskeys: keys };
}

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const sequencePattern = /^(0|[1-9][0-9]*)$/u;
const clientMessageIdPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;

function isUuid(value: unknown): value is Uuid {
  return typeof value === 'string' && uuidPattern.test(value);
}

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

export function parseSessionPrincipal(value: unknown): SessionPrincipal | null {
  return parseCurrentPrincipalAuthorization(value);
}

export function parseAccountRecord(value: unknown): AccountRecord | null {
  if (
    !isRecord(value) ||
    value.accountAccess !== 'member' ||
    !isUuid(value.userId) ||
    typeof value.displayName !== 'string' ||
    typeof value.email !== 'string' ||
    !domainStatuses.includes(value.domainStatus as DomainStatus) ||
    (value.status !== 'active' && value.status !== 'deactivated') ||
    !Array.isArray(value.functionalGrants) ||
    value.functionalGrants.some((grant) => !functionalGrants.includes(grant as FunctionalGrant)) ||
    new Set(value.functionalGrants).size !== value.functionalGrants.length
  ) {
    return null;
  }
  return Object.freeze({
    accountAccess: 'member',
    displayName: value.displayName,
    domainStatus: value.domainStatus as DomainStatus,
    email: value.email,
    functionalGrants: Object.freeze([...value.functionalGrants] as FunctionalGrant[]),
    status: value.status,
    userId: value.userId,
  });
}

export function parseChatListResponse(value: unknown): ChatListResponse | null {
  if (
    !isRecord(value) ||
    value.contractVersion !== chatListContractVersion ||
    !Array.isArray(value.items)
  ) {
    return null;
  }
  const items: AvailableChat[] = [];
  for (const item of value.items) {
    if (
      !isRecord(item) ||
      !isRecord(item.capabilities) ||
      !isUuid(item.id) ||
      (item.kind !== 'direct' && item.kind !== 'group') ||
      typeof item.capabilities.canRead !== 'boolean' ||
      typeof item.capabilities.canWrite !== 'boolean'
    ) {
      return null;
    }
    items.push(
      Object.freeze({
        capabilities: Object.freeze({
          canRead: item.capabilities.canRead,
          canWrite: item.capabilities.canWrite,
        }),
        id: item.id,
        kind: item.kind,
      }),
    );
  }
  return Object.freeze({ contractVersion: chatListContractVersion, items: Object.freeze(items) });
}

function parseTextMessage(value: unknown): TextMessage | null {
  if (
    !isRecord(value) ||
    typeof value.body !== 'string' ||
    value.body.length < 1 ||
    value.body.length > 20_000 ||
    !isUuid(value.chatId) ||
    typeof value.chatSequence !== 'string' ||
    !sequencePattern.test(value.chatSequence) ||
    typeof value.clientMessageId !== 'string' ||
    !clientMessageIdPattern.test(value.clientMessageId) ||
    typeof value.createdAt !== 'string' ||
    !Number.isFinite(Date.parse(value.createdAt)) ||
    !isUuid(value.id) ||
    !isUuid(value.senderAccountId)
  ) {
    return null;
  }
  return Object.freeze({
    body: value.body,
    chatId: value.chatId,
    chatSequence: value.chatSequence,
    clientMessageId: value.clientMessageId,
    createdAt: value.createdAt,
    id: value.id,
    senderAccountId: value.senderAccountId,
  });
}

function parseMessages(value: unknown): readonly TextMessage[] | null {
  if (!Array.isArray(value)) return null;
  const messages: TextMessage[] = [];
  for (const item of value) {
    const message = parseTextMessage(item);
    if (message === null) return null;
    messages.push(message);
  }
  return Object.freeze(messages);
}

export function parseMessageHistoryPage(value: unknown): MessageHistoryPage | null {
  if (
    !isRecord(value) ||
    value.contractVersion !== messageHistoryContractVersion ||
    typeof value.hasMore !== 'boolean' ||
    (value.nextAfterSequence !== null &&
      (typeof value.nextAfterSequence !== 'string' ||
        !sequencePattern.test(value.nextAfterSequence))) ||
    (value.nextBeforeSequence !== null &&
      (typeof value.nextBeforeSequence !== 'string' ||
        !sequencePattern.test(value.nextBeforeSequence)))
  ) {
    return null;
  }
  const items = parseMessages(value.items);
  if (items === null) return null;
  return Object.freeze({
    contractVersion: messageHistoryContractVersion,
    hasMore: value.hasMore,
    items,
    nextAfterSequence: value.nextAfterSequence,
    nextBeforeSequence: value.nextBeforeSequence,
  });
}

export function parseCreateTextMessageResponse(value: unknown): CreateTextMessageResponse | null {
  if (
    !isRecord(value) ||
    value.contractVersion !== messageFlowContractVersion ||
    (value.outcome !== 'created' && value.outcome !== 'replayed')
  ) {
    return null;
  }
  const message = parseTextMessage(value.message);
  if (message === null) return null;
  return Object.freeze({
    contractVersion: messageFlowContractVersion,
    message,
    outcome: value.outcome,
  });
}

export function parseRealtimeSubscribeResult(value: unknown): RealtimeSubscribeResult | null {
  if (
    !isRecord(value) ||
    value.contractVersion !== realtimeContractVersion ||
    typeof value.joined !== 'boolean' ||
    typeof value.nextAfterSequence !== 'string' ||
    !sequencePattern.test(value.nextAfterSequence)
  ) {
    return null;
  }
  const history = parseMessages(value.history);
  if (history === null) return null;
  return Object.freeze({
    contractVersion: realtimeContractVersion,
    history,
    joined: value.joined,
    nextAfterSequence: value.nextAfterSequence,
  });
}

export type ChatListOutcome =
  | { readonly kind: 'configuration-error' }
  | { readonly kind: 'ready' }
  | { readonly kind: 'reload-required' };

export function resolveChatListOutcome(
  chatCount: number,
  zeroWasSeenBeforeReload: boolean,
): ChatListOutcome {
  if (!Number.isSafeInteger(chatCount) || chatCount < 0) {
    return Object.freeze({ kind: 'configuration-error' });
  }
  if (chatCount > 0) {
    return Object.freeze({ kind: 'ready' });
  }
  return Object.freeze({
    kind: zeroWasSeenBeforeReload ? 'configuration-error' : 'reload-required',
  });
}

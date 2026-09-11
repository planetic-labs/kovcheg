'use client';

import {
  parseMessageCreatedRealtimeEvent,
  realtimeSocketEvents,
  realtimeSocketPath,
} from '@kovcheg/contracts';
import type { AvailableChat, UserId, Uuid } from '@kovcheg/contracts';
import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import type { FormEvent } from 'react';
import { io } from 'socket.io-client';

import { resolveChatListOutcome } from '../a6/chat-list-state';
import {
  parseChatListResponse,
  parseCreateTextMessageResponse,
  parseMessageHistoryPage,
  parseRealtimeSubscribeResult,
} from '../a6/contracts';
import {
  createMessageHistoryCatchUp,
  emptyMessageTimeline,
  enqueueOptimisticMessage,
  failOptimisticMessage,
  mergeStoredMessages,
  mergeReadHistory,
  pendingMessageTimeline,
} from '../a6/message-state';
import type { MessageTimelineState, TimelineItem } from '../a6/message-state';
import { acceptRealtimeEvent, emptyRealtimeProjection } from '../a6/realtime-state';
import { TextComposer } from './text-composer';

const zeroChatMarker = 'kovcheg:a6-zero-chat-seen';
const maximumRenderedItems = 400;

type ConnectionState = 'connected' | 'connecting' | 'offline';
type ListState = 'checking' | 'error' | 'ready';

interface ChatHistoryScope {
  readonly chatId: Uuid;
  readonly abort: AbortController;
  readonly catchUp: ReturnType<typeof createMessageHistoryCatchUp>;
  readonly startRealtime: () => void;
  initialCursor: string | null;
  loadingLatest: boolean;
}

async function jsonOrNull(response: Response): Promise<unknown> {
  return response.json().catch(() => null);
}

function boundedTimeline(state: MessageTimelineState): MessageTimelineState {
  if (state.items.length <= maximumRenderedItems) return state;
  return Object.freeze({
    ...state,
    items: Object.freeze(state.items.slice(-maximumRenderedItems)),
  });
}

function chatLabel(chat: AvailableChat): string {
  const kind = chat.kind === 'direct' ? 'Личный чат' : 'Групповой чат';
  return `${kind} · ${chat.id.slice(-6)}`;
}

function isSessionFailure(status: number): boolean {
  return status === 401;
}

export function ChatPanel({
  onSessionInvalid,
  principalUserId,
}: Readonly<{ onSessionInvalid: () => void; principalUserId: UserId }>) {
  const [chats, setChats] = useState<readonly AvailableChat[]>(Object.freeze([]));
  const [listState, setListState] = useState<ListState>('checking');
  const [selectedChatId, setSelectedChatId] = useState<Uuid | null>(null);
  const [mobileConversation, setMobileConversation] = useState(false);
  const [timeline, setTimeline] = useState<MessageTimelineState>(emptyMessageTimeline);
  const [historyError, setHistoryError] = useState(false);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [hasOlder, setHasOlder] = useState(false);
  const [nextBeforeSequence, setNextBeforeSequence] = useState<string | null>(null);
  const [connection, setConnection] = useState<ConnectionState>('connecting');
  const [draft, setDraft] = useState('');
  const chatButtonRefs = useRef(new Map<Uuid, HTMLButtonElement>());
  const mobileBackRef = useRef<HTMLButtonElement>(null);
  const messageListRef = useRef<HTMLDivElement>(null);
  const scrollPositionRef = useRef<{
    chatId: Uuid;
    atEnd: boolean;
    anchorId: string | null;
    anchorOffset: number;
  } | null>(null);
  const timelineRef = useRef(timeline);
  const historyScopeRef = useRef<ChatHistoryScope | null>(null);
  const realtimeProjectionRef = useRef(emptyRealtimeProjection());
  const loadedChatsRef = useRef(false);
  const listRequestRef = useRef(0);
  const draftsRef = useRef(new Map<Uuid, string>());
  const pendingSendsRef = useRef(new Map<Uuid, MessageTimelineState>());

  const rememberPending = useCallback((chatId: Uuid, state: MessageTimelineState) => {
    const pending = pendingMessageTimeline(state);
    if (pending.items.length === 0) pendingSendsRef.current.delete(chatId);
    else pendingSendsRef.current.set(chatId, pending);
  }, []);

  const updateTimeline = useCallback(
    (update: (current: MessageTimelineState) => MessageTimelineState) => {
      const next = boundedTimeline(update(timelineRef.current));
      const chatId = historyScopeRef.current?.chatId;
      if (chatId !== undefined) rememberPending(chatId, next);
      timelineRef.current = next;
      setTimeline(next);
    },
    [rememberPending],
  );

  const loadChats = useCallback(async () => {
    const request = ++listRequestRef.current;
    if (!loadedChatsRef.current) setListState('checking');
    try {
      const response = await fetch('/bff/chats', { cache: 'no-store' });
      if (request !== listRequestRef.current) return;
      if (isSessionFailure(response.status)) {
        onSessionInvalid();
        return;
      }
      const payload = response.ok ? parseChatListResponse(await jsonOrNull(response)) : null;
      if (request !== listRequestRef.current) return;
      if (response.status === 403) {
        pendingSendsRef.current.clear();
        draftsRef.current.clear();
        setChats(Object.freeze([]));
        setSelectedChatId(null);
        setListState('error');
        return;
      }
      if (payload === null) {
        setListState('error');
        return;
      }
      const readable = payload.items.filter((chat) => chat.capabilities.canRead);
      for (const chatId of pendingSendsRef.current.keys()) {
        if (!readable.some((chat) => chat.id === chatId)) pendingSendsRef.current.delete(chatId);
      }
      for (const chatId of draftsRef.current.keys()) {
        if (!readable.some((chat) => chat.id === chatId)) draftsRef.current.delete(chatId);
      }
      if (loadedChatsRef.current && readable.length === 0) {
        setChats(Object.freeze([]));
        setSelectedChatId(null);
        setListState('error');
        return;
      }
      const sawZero = globalThis.sessionStorage.getItem(zeroChatMarker) === '1';
      const outcome = resolveChatListOutcome(readable.length, sawZero);
      if (outcome.kind === 'reload-required') {
        globalThis.sessionStorage.setItem(zeroChatMarker, '1');
        globalThis.location.reload();
        return;
      }
      if (outcome.kind === 'configuration-error') {
        setListState('error');
        return;
      }
      globalThis.sessionStorage.removeItem(zeroChatMarker);
      setChats(Object.freeze(readable));
      loadedChatsRef.current = true;
      setSelectedChatId((current) =>
        current !== null && readable.some((chat) => chat.id === current)
          ? current
          : (readable[0]?.id ?? null),
      );
      setListState('ready');
    } catch {
      if (request === listRequestRef.current) setListState('error');
    }
  }, [onSessionInvalid]);

  useEffect(() => {
    void loadChats();
  }, [loadChats]);

  useEffect(() => {
    const pending = pendingSendsRef.current;
    const drafts = draftsRef.current;
    return () => {
      pending.clear();
      drafts.clear();
    };
  }, []);

  const selectedChat = chats.find((chat) => chat.id === selectedChatId) ?? null;
  // A refreshed list can select another chat before its history effect runs.
  // Never render the previous conversation under that new selection.
  const visibleItems = historyScopeRef.current?.chatId === selectedChatId ? timeline.items : [];

  const rememberScrollPosition = useCallback(() => {
    const list = messageListRef.current;
    const scope = historyScopeRef.current;
    if (
      list === null ||
      list.clientHeight === 0 ||
      scope?.chatId !== selectedChatId ||
      scope.initialCursor === null
    )
      return;
    const top = list.getBoundingClientRect().top;
    const anchor = Array.from(list.children).find(
      (row) => row.hasAttribute('data-message-id') && row.getBoundingClientRect().bottom > top,
    );
    scrollPositionRef.current = {
      chatId: scope.chatId,
      atEnd: list.scrollHeight - list.clientHeight - list.scrollTop <= 2,
      anchorId: anchor?.getAttribute('data-message-id') ?? null,
      anchorOffset: anchor === undefined ? 0 : anchor.getBoundingClientRect().top - top,
    };
  }, [selectedChatId]);

  const restoreScrollPosition = useCallback(() => {
    const list = messageListRef.current;
    const scope = historyScopeRef.current;
    // Pending sends or a late render from another chat must not consume initial positioning.
    if (
      list === null ||
      list.clientHeight === 0 ||
      scope?.chatId !== selectedChatId ||
      scope.initialCursor === null
    )
      return;
    const previous = scrollPositionRef.current;
    if (previous?.chatId !== selectedChatId || previous.atEnd) {
      list.scrollTop = list.scrollHeight;
    } else {
      const anchor = Array.from(list.children).find(
        (row) =>
          previous.anchorId !== null && row.getAttribute('data-message-id') === previous.anchorId,
      );
      // Preserve a visible message, including after prepend or bounded-history eviction.
      // If the anchor itself was evicted, the earliest retained message is the closest boundary.
      list.scrollTop =
        anchor === undefined
          ? 0
          : list.scrollTop +
            anchor.getBoundingClientRect().top -
            list.getBoundingClientRect().top -
            previous.anchorOffset;
    }
    rememberScrollPosition();
  }, [rememberScrollPosition, selectedChatId]);

  useLayoutEffect(() => {
    restoreScrollPosition();
  }, [restoreScrollPosition, visibleItems, mobileConversation, historyLoading, hasOlder]);

  useLayoutEffect(() => {
    const list = messageListRef.current;
    if (list === null) return;
    const observer = new ResizeObserver(restoreScrollPosition);
    observer.observe(list);
    return () => observer.disconnect();
  }, [restoreScrollPosition]);

  const requestHistory = useCallback(
    async (chatId: Uuid, query: URLSearchParams, signal: AbortSignal) => {
      const response = await fetch(`/bff/chats/${chatId}/messages?${query.toString()}`, {
        cache: 'no-store',
        signal,
      });
      if (signal.aborted) return null;
      if (isSessionFailure(response.status)) {
        onSessionInvalid();
        return null;
      }
      if (response.status === 403) {
        if (historyScopeRef.current?.chatId === chatId) {
          updateTimeline(() => emptyMessageTimeline());
          setChats((current) => current.filter((chat) => chat.id !== chatId));
          setSelectedChatId(null);
        }
        void loadChats();
      }
      return response.ok ? parseMessageHistoryPage(await jsonOrNull(response)) : null;
    },
    [loadChats, onSessionInvalid, updateTimeline],
  );

  const loadLatest = useCallback(
    async (scope: ChatHistoryScope) => {
      if (scope.loadingLatest || scope.abort.signal.aborted) return;
      scope.loadingLatest = true;
      setHistoryLoading(true);
      setHistoryError(false);
      const page = await requestHistory(
        scope.chatId,
        new URLSearchParams({ limit: '50' }),
        scope.abort.signal,
      ).catch(() => null);
      scope.loadingLatest = false;
      if (historyScopeRef.current !== scope) return;
      if (page === null) {
        setHistoryError(true);
      } else {
        updateTimeline((current) => mergeReadHistory(current, page.items));
        setHasOlder(page.hasMore && page.nextBeforeSequence !== null);
        setNextBeforeSequence(page.nextBeforeSequence);
        if (scope.initialCursor === null) {
          scope.initialCursor = timelineRef.current.historySequence;
          scope.catchUp.request();
          scope.startRealtime();
        }
      }
      setHistoryLoading(false);
    },
    [requestHistory, updateTimeline],
  );

  useEffect(() => {
    const initial =
      (selectedChatId === null ? null : pendingSendsRef.current.get(selectedChatId)) ??
      emptyMessageTimeline();
    timelineRef.current = initial;
    setTimeline(initial);
    setDraft(selectedChatId === null ? '' : (draftsRef.current.get(selectedChatId) ?? ''));
    setHasOlder(false);
    setNextBeforeSequence(null);
    realtimeProjectionRef.current = emptyRealtimeProjection();
    if (selectedChatId === null) return;
    setConnection('connecting');
    const socket = io({
      autoConnect: false,
      path: realtimeSocketPath,
      transports: ['polling', 'websocket'],
      withCredentials: true,
    });
    const abort = new AbortController();
    const catchUp = createMessageHistoryCatchUp({
      readCursor: () => scope.initialCursor,
      readPage: (cursor) =>
        requestHistory(
          selectedChatId,
          new URLSearchParams({ afterSequence: cursor, limit: '100' }),
          abort.signal,
        ),
      applyPage: (messages) => updateTimeline((current) => mergeReadHistory(current, messages)),
      onFailure: () => setConnection('offline'),
      onSuccess: () => {
        setHistoryError(false);
        if (socket.connected) setConnection('connected');
      },
    });
    const scope: ChatHistoryScope = {
      abort,
      catchUp,
      chatId: selectedChatId,
      initialCursor: null,
      loadingLatest: false,
      startRealtime: () => {
        socket.connect();
      },
    };
    historyScopeRef.current = scope;
    void loadLatest(scope);

    function resumeHistory() {
      if (document.visibilityState === 'visible') catchUp.request();
    }
    window.addEventListener('online', resumeHistory);
    document.addEventListener('visibilitychange', resumeHistory);

    socket.on(realtimeSocketEvents.ready, () => {
      setConnection('connected');
      void loadChats();
      const afterSequence = timelineRef.current.historySequence;
      socket
        .timeout(5_000)
        .emit(
          realtimeSocketEvents.subscribe,
          { afterSequence, chatId: selectedChatId },
          (error: Error | null, value: unknown) => {
            if (historyScopeRef.current !== scope) return;
            if (error !== null) {
              setConnection('offline');
              return;
            }
            const result = parseRealtimeSubscribeResult(value);
            if (result === null || !result.joined) {
              setConnection('offline');
              return;
            }
            updateTimeline((current) => mergeReadHistory(current, result.history));
            catchUp.request();
          },
        );
    });
    socket.on(realtimeSocketEvents.messageCreated, (value: unknown) => {
      const event = parseMessageCreatedRealtimeEvent(value);
      if (event === null || event.payload.chatId !== selectedChatId) {
        return;
      }
      const accepted = acceptRealtimeEvent(realtimeProjectionRef.current, event);
      realtimeProjectionRef.current = accepted.state;
      if (!accepted.accepted) return;
      catchUp.request();
    });
    socket.on(realtimeSocketEvents.error, () => {
      setConnection('offline');
      void fetch('/bff/session', { cache: 'no-store' })
        .then((response) => {
          if (historyScopeRef.current !== scope) return;
          if (isSessionFailure(response.status)) onSessionInvalid();
        })
        .catch(() => undefined);
    });
    socket.on('connect_error', () => setConnection('offline'));
    socket.on('disconnect', () => {
      setConnection('connecting');
      void loadChats();
    });
    return () => {
      historyScopeRef.current = null;
      catchUp.dispose();
      abort.abort();
      window.removeEventListener('online', resumeHistory);
      document.removeEventListener('visibilitychange', resumeHistory);
      socket.removeAllListeners();
      socket.disconnect();
    };
  }, [loadChats, loadLatest, onSessionInvalid, requestHistory, selectedChatId, updateTimeline]);

  async function loadOlderMessages(): Promise<void> {
    const scope = historyScopeRef.current;
    if (scope === null || nextBeforeSequence === null || historyLoading) return;
    setHistoryLoading(true);
    const page = await requestHistory(
      scope.chatId,
      new URLSearchParams({ beforeSequence: nextBeforeSequence, limit: '50' }),
      scope.abort.signal,
    ).catch(() => null);
    if (historyScopeRef.current !== scope) return;
    if (page === null) {
      setHistoryError(true);
    } else {
      updateTimeline((current) => mergeStoredMessages(current, page.items));
      const atRenderLimit = timelineRef.current.items.length >= maximumRenderedItems;
      setHasOlder(!atRenderLimit && page.hasMore && page.nextBeforeSequence !== null);
      setNextBeforeSequence(page.nextBeforeSequence);
    }
    setHistoryLoading(false);
  }

  async function sendMessage(
    clientMessageId: string,
    text: string,
    clearDraft: boolean,
  ): Promise<void> {
    if (selectedChat === null || !selectedChat.capabilities.canWrite) return;
    const scope = historyScopeRef.current;
    if (scope === null || scope.chatId !== selectedChat.id) return;
    const chatId = selectedChat.id;
    function updateSend(update: (current: MessageTimelineState) => MessageTimelineState) {
      const pending = pendingSendsRef.current.get(chatId);
      // Permission removal or unmount invalidates a late result, including a prior session.
      if (pending === undefined) return;
      if (historyScopeRef.current?.chatId === chatId) updateTimeline(update);
      else rememberPending(chatId, update(pending));
    }
    updateTimeline((current) =>
      enqueueOptimisticMessage(current, {
        clientMessageId,
        senderUserId: principalUserId,
        text,
      }),
    );
    if (clearDraft) {
      draftsRef.current.delete(selectedChat.id);
      setDraft('');
    }
    try {
      const response = await fetch(`/bff/chats/${selectedChat.id}/messages`, {
        body: JSON.stringify({ clientMessageId, text }),
        headers: { 'content-type': 'application/json' },
        method: 'POST',
      });
      if (!pendingSendsRef.current.has(chatId)) return;
      if (isSessionFailure(response.status)) {
        onSessionInvalid();
        return;
      }
      if (response.status === 403) {
        updateSend((current) => failOptimisticMessage(current, clientMessageId));
        await loadChats();
        return;
      }
      const payload = response.ok
        ? parseCreateTextMessageResponse(await jsonOrNull(response))
        : null;
      if (!pendingSendsRef.current.has(chatId)) return;
      if (payload === null) {
        updateSend((current) => failOptimisticMessage(current, clientMessageId));
        return;
      }
      updateSend((current) => mergeStoredMessages(current, [payload.message]));
      if (historyScopeRef.current?.chatId === chatId) historyScopeRef.current.catchUp.request();
    } catch {
      updateSend((current) => failOptimisticMessage(current, clientMessageId));
    }
  }

  function submitDraft(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    const text = draft.trim();
    if (text.length < 1) return;
    void sendMessage(`web:${crypto.randomUUID()}`, text, true);
  }

  function openConversation(chatId: Uuid): void {
    if (selectedChatId !== null) draftsRef.current.set(selectedChatId, draft);
    if (chatId !== selectedChatId) {
      const empty = emptyMessageTimeline();
      timelineRef.current = empty;
      setTimeline(empty);
      setHasOlder(false);
      setHistoryError(false);
      setDraft(draftsRef.current.get(chatId) ?? '');
    }
    setSelectedChatId(chatId);
    if (globalThis.matchMedia('(max-width: 820px)').matches) {
      scrollPositionRef.current = null;
      setMobileConversation(true);
      requestAnimationFrame(() => mobileBackRef.current?.focus());
    }
  }

  function returnToChatList(): void {
    setMobileConversation(false);
    requestAnimationFrame(() => {
      if (selectedChatId !== null) chatButtonRefs.current.get(selectedChatId)?.focus();
    });
  }

  if (!loadedChatsRef.current && listState !== 'ready') {
    return (
      <section className="workspace-stage">
        <div
          aria-atomic="true"
          aria-live={listState === 'error' ? 'assertive' : 'polite'}
          className="startup-panel"
          role={listState === 'error' ? 'alert' : 'status'}
        >
          <p className="eyebrow">Чаты</p>
          <h1>
            {listState === 'checking'
              ? 'Проверяем стартовую конфигурацию…'
              : 'Не удалось завершить стартовую настройку чатов'}
          </h1>
          <p>
            {listState === 'checking'
              ? 'Подтверждаем доступ и доступные разговоры.'
              : 'Список разговоров не получен. Повторите проверку; доступ не подменяется пустым состоянием.'}
          </p>
          {listState === 'error' && (
            <button
              className="primary-button compact"
              onClick={() => void loadChats()}
              type="button"
            >
              Повторить
            </button>
          )}
        </div>
      </section>
    );
  }

  return (
    <section className={`chat-workspace${mobileConversation ? ' mobile-conversation' : ''}`}>
      <aside aria-label="Доступные чаты" className="chat-list-panel">
        <header>
          <p className="eyebrow">Чаты</p>
          <h1>Разговоры</h1>
        </header>
        {listState === 'error' && (
          <p role="alert">
            Список не обновлён или доступ изменился.{' '}
            <button type="button" onClick={() => void loadChats()}>
              Повторить
            </button>
          </p>
        )}
        <ul className="chat-list">
          {chats.map((chat) => (
            <li key={chat.id}>
              <button
                aria-current={chat.id === selectedChatId ? 'page' : undefined}
                className="chat-list-item"
                onClick={() => openConversation(chat.id)}
                ref={(element) => {
                  if (element === null) chatButtonRefs.current.delete(chat.id);
                  else chatButtonRefs.current.set(chat.id, element);
                }}
                type="button"
              >
                <strong>{chatLabel(chat)}</strong>
                <span>{chat.capabilities.canWrite ? 'Чтение и запись' : 'Только чтение'}</span>
              </button>
            </li>
          ))}
        </ul>
      </aside>

      <article className="conversation-panel">
        {selectedChat === null ? (
          <p className="workspace-stage">Выберите доступный чат</p>
        ) : (
          <>
            <header className="conversation-header">
              <button
                aria-label="Вернуться к списку чатов"
                className="mobile-back"
                onClick={returnToChatList}
                ref={mobileBackRef}
                type="button"
              >
                ←
              </button>
              <div>
                <h2>{chatLabel(selectedChat)}</h2>
                <p aria-atomic="true" aria-live="polite" role="status">
                  {connection === 'connected'
                    ? 'Обновления подключены'
                    : connection === 'connecting'
                      ? 'Переподключаемся…'
                      : 'Нет соединения — сообщения сохранят статус'}
                </p>
              </div>
            </header>

            <div
              aria-busy={historyLoading}
              aria-live="polite"
              aria-relevant="additions text"
              className="message-list"
              onScroll={rememberScrollPosition}
              ref={messageListRef}
              role="log"
            >
              {historyLoading && visibleItems.length === 0 && (
                <p role="status">Загружаем сообщения…</p>
              )}
              {hasOlder && (
                <button
                  className="history-button"
                  disabled={historyLoading}
                  onClick={() => void loadOlderMessages()}
                  type="button"
                >
                  {historyLoading ? 'Загружаем…' : 'Показать более ранние сообщения'}
                </button>
              )}
              {historyError && (
                <button
                  className="history-button error"
                  onClick={() => {
                    const scope = historyScopeRef.current;
                    if (scope !== null) void loadLatest(scope);
                  }}
                  type="button"
                >
                  История недоступна. Повторить
                </button>
              )}
              {visibleItems.map((item) => (
                <MessageBubble
                  item={item}
                  key={item.id}
                  onRetry={(clientMessageId, text) =>
                    void sendMessage(clientMessageId, text, false)
                  }
                  principalUserId={principalUserId}
                />
              ))}
            </div>

            {selectedChat.capabilities.canWrite ? (
              <TextComposer draft={draft} onDraftChange={setDraft} onSubmit={submitDraft} />
            ) : (
              <p aria-live="polite" className="read-only-notice" role="status">
                В этом чате доступно только чтение.
              </p>
            )}
          </>
        )}
      </article>
    </section>
  );
}

function MessageBubble({
  item,
  onRetry,
  principalUserId,
}: Readonly<{
  item: TimelineItem;
  onRetry: (clientMessageId: string, text: string) => void;
  principalUserId: UserId;
}>) {
  const outgoing =
    item.kind === 'optimistic'
      ? item.senderUserId === principalUserId
      : item.message.senderAccountId === principalUserId;
  const text = item.kind === 'optimistic' ? item.text : item.message.body;
  return (
    <article
      aria-label={outgoing ? 'Исходящее сообщение' : 'Входящее сообщение'}
      className={`message-row${outgoing ? ' outgoing' : ''}`}
      data-message-id={item.clientMessageId}
    >
      <div className={`message-bubble${item.kind === 'optimistic' ? ` ${item.status}` : ''}`}>
        <p>{text}</p>
        <small>
          {item.kind === 'stored'
            ? new Intl.DateTimeFormat('ru', {
                hour: '2-digit',
                minute: '2-digit',
              }).format(new Date(item.message.createdAt))
            : item.status === 'sending'
              ? 'Отправляем…'
              : 'Не отправлено'}
        </small>
        {item.kind === 'optimistic' && item.status === 'failed' && (
          <button onClick={() => onRetry(item.clientMessageId, item.text)} type="button">
            Повторить
          </button>
        )}
      </div>
    </article>
  );
}

'use client';

import {
  parseMessageCreatedRealtimeEvent,
  realtimeSocketEvents,
  realtimeSocketPath,
} from '@kovcheg/contracts';
import type { AvailableChat, UserId, Uuid } from '@kovcheg/contracts';
import { useCallback, useEffect, useRef, useState } from 'react';
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
  emptyMessageTimeline,
  enqueueOptimisticMessage,
  failOptimisticMessage,
  mergeStoredMessages,
} from '../a6/message-state';
import type { MessageTimelineState, TimelineItem } from '../a6/message-state';
import { acceptRealtimeEvent, emptyRealtimeProjection } from '../a6/realtime-state';

const zeroChatMarker = 'kovcheg:a6-zero-chat-seen';
const maximumRenderedItems = 400;

type ConnectionState = 'connected' | 'connecting' | 'offline';
type ListState = 'checking' | 'error' | 'ready';

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
  const timelineRef = useRef(timeline);
  const realtimeProjectionRef = useRef(emptyRealtimeProjection());

  const updateTimeline = useCallback(
    (update: (current: MessageTimelineState) => MessageTimelineState) => {
      setTimeline((current) => {
        const next = boundedTimeline(update(current));
        timelineRef.current = next;
        return next;
      });
    },
    [],
  );

  const loadChats = useCallback(async () => {
    setListState('checking');
    try {
      const response = await fetch('/bff/chats', { cache: 'no-store' });
      if (isSessionFailure(response.status)) {
        onSessionInvalid();
        return;
      }
      const payload = response.ok ? parseChatListResponse(await jsonOrNull(response)) : null;
      if (payload === null) {
        setListState('error');
        return;
      }
      const readable = payload.items.filter((chat) => chat.capabilities.canRead);
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
      setSelectedChatId((current) =>
        current !== null && readable.some((chat) => chat.id === current)
          ? current
          : (readable[0]?.id ?? null),
      );
      setListState('ready');
    } catch {
      setListState('error');
    }
  }, [onSessionInvalid]);

  useEffect(() => {
    void loadChats();
  }, [loadChats]);

  const selectedChat = chats.find((chat) => chat.id === selectedChatId) ?? null;

  const requestHistory = useCallback(
    async (chatId: Uuid, query: URLSearchParams) => {
      const response = await fetch(`/bff/chats/${chatId}/messages?${query.toString()}`, {
        cache: 'no-store',
      });
      if (isSessionFailure(response.status)) {
        onSessionInvalid();
        return null;
      }
      if (response.status === 403) void loadChats();
      return response.ok ? parseMessageHistoryPage(await jsonOrNull(response)) : null;
    },
    [loadChats, onSessionInvalid],
  );

  const loadLatest = useCallback(
    async (chatId: Uuid) => {
      setHistoryLoading(true);
      setHistoryError(false);
      const page = await requestHistory(chatId, new URLSearchParams({ limit: '50' })).catch(
        () => null,
      );
      if (page === null) {
        setHistoryError(true);
      } else {
        updateTimeline((current) => mergeStoredMessages(current, page.items));
        setHasOlder(page.hasMore && page.nextBeforeSequence !== null);
        setNextBeforeSequence(page.nextBeforeSequence);
      }
      setHistoryLoading(false);
    },
    [requestHistory, updateTimeline],
  );

  useEffect(() => {
    const empty = emptyMessageTimeline();
    timelineRef.current = empty;
    setTimeline(empty);
    setDraft('');
    setHasOlder(false);
    setNextBeforeSequence(null);
    realtimeProjectionRef.current = emptyRealtimeProjection();
    if (selectedChatId !== null) void loadLatest(selectedChatId);
  }, [loadLatest, selectedChatId]);

  const catchUp = useCallback(
    async (chatId: Uuid, initialAfterSequence: string) => {
      let cursor = initialAfterSequence;
      for (let pageNumber = 0; pageNumber < 20; pageNumber += 1) {
        const page = await requestHistory(
          chatId,
          new URLSearchParams({ afterSequence: cursor, limit: '100' }),
        ).catch(() => null);
        if (page === null) {
          setConnection('offline');
          return;
        }
        updateTimeline((current) => mergeStoredMessages(current, page.items));
        if (!page.hasMore) return;
        if (page.nextAfterSequence === null || page.nextAfterSequence === cursor) {
          setConnection('offline');
          return;
        }
        cursor = page.nextAfterSequence;
      }
      setConnection('offline');
    },
    [requestHistory, updateTimeline],
  );

  useEffect(() => {
    if (selectedChatId === null) return;
    setConnection('connecting');
    const socket = io({
      path: realtimeSocketPath,
      transports: ['polling', 'websocket'],
      withCredentials: true,
    });

    socket.on(realtimeSocketEvents.ready, () => {
      setConnection('connected');
      void loadChats();
      const afterSequence = timelineRef.current.lastSequence;
      socket
        .timeout(5_000)
        .emit(
          realtimeSocketEvents.subscribe,
          { afterSequence, chatId: selectedChatId },
          (error: Error | null, value: unknown) => {
            if (error !== null) {
              setConnection('offline');
              return;
            }
            const result = parseRealtimeSubscribeResult(value);
            if (result === null || !result.joined) {
              setConnection('offline');
              return;
            }
            updateTimeline((current) => mergeStoredMessages(current, result.history));
            void catchUp(selectedChatId, result.nextAfterSequence);
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
      void catchUp(selectedChatId, timelineRef.current.lastSequence);
    });
    socket.on(realtimeSocketEvents.error, () => {
      setConnection('offline');
      void fetch('/bff/session', { cache: 'no-store' })
        .then((response) => {
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
      socket.removeAllListeners();
      socket.disconnect();
    };
  }, [catchUp, loadChats, onSessionInvalid, selectedChatId, updateTimeline]);

  async function loadOlderMessages(): Promise<void> {
    if (selectedChatId === null || nextBeforeSequence === null || historyLoading) return;
    setHistoryLoading(true);
    const page = await requestHistory(
      selectedChatId,
      new URLSearchParams({ beforeSequence: nextBeforeSequence, limit: '50' }),
    ).catch(() => null);
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
    updateTimeline((current) =>
      enqueueOptimisticMessage(current, {
        clientMessageId,
        senderUserId: principalUserId,
        text,
      }),
    );
    if (clearDraft) setDraft('');
    try {
      const response = await fetch(`/bff/chats/${selectedChat.id}/messages`, {
        body: JSON.stringify({ clientMessageId, text }),
        headers: { 'content-type': 'application/json' },
        method: 'POST',
      });
      if (isSessionFailure(response.status)) {
        onSessionInvalid();
        return;
      }
      if (response.status === 403) {
        updateTimeline((current) => failOptimisticMessage(current, clientMessageId));
        await loadChats();
        return;
      }
      const payload = response.ok
        ? parseCreateTextMessageResponse(await jsonOrNull(response))
        : null;
      if (payload === null) {
        updateTimeline((current) => failOptimisticMessage(current, clientMessageId));
        return;
      }
      updateTimeline((current) => mergeStoredMessages(current, [payload.message]));
    } catch {
      updateTimeline((current) => failOptimisticMessage(current, clientMessageId));
    }
  }

  function submitDraft(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    const text = draft.trim();
    if (text.length < 1) return;
    void sendMessage(`web:${crypto.randomUUID()}`, text, true);
  }

  if (listState !== 'ready') {
    return (
      <section className="workspace-stage">
        <div className="startup-panel">
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
        <div className="chat-list" role="list">
          {chats.map((chat) => (
            <button
              aria-current={chat.id === selectedChatId ? 'page' : undefined}
              className="chat-list-item"
              key={chat.id}
              onClick={() => {
                setSelectedChatId(chat.id);
                setMobileConversation(true);
              }}
              role="listitem"
              type="button"
            >
              <strong>{chatLabel(chat)}</strong>
              <span>{chat.capabilities.canWrite ? 'Чтение и запись' : 'Только чтение'}</span>
            </button>
          ))}
        </div>
      </aside>

      <article className="conversation-panel">
        {selectedChat === null ? null : (
          <>
            <header className="conversation-header">
              <button
                aria-label="Вернуться к списку чатов"
                className="mobile-back"
                onClick={() => setMobileConversation(false)}
                type="button"
              >
                ←
              </button>
              <div>
                <h2>{chatLabel(selectedChat)}</h2>
                <p aria-live="polite">
                  {connection === 'connected'
                    ? 'Обновления подключены'
                    : connection === 'connecting'
                      ? 'Переподключаемся…'
                      : 'Нет соединения — сообщения сохранят статус'}
                </p>
              </div>
            </header>

            <div aria-busy={historyLoading} aria-live="polite" className="message-list">
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
                  onClick={() => void loadLatest(selectedChat.id)}
                  type="button"
                >
                  История недоступна. Повторить
                </button>
              )}
              {timeline.items.map((item) => (
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
              <form className="composer" onSubmit={submitDraft}>
                <label className="visually-hidden" htmlFor="message-draft">
                  Текст сообщения
                </label>
                <textarea
                  id="message-draft"
                  maxLength={20_000}
                  onChange={(event) => setDraft(event.currentTarget.value)}
                  onKeyDown={(event) => {
                    if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
                      event.preventDefault();
                      event.currentTarget.form?.requestSubmit();
                    }
                  }}
                  placeholder="Сообщение"
                  rows={2}
                  value={draft}
                />
                <span className="composer-hint">Ctrl/⌘ + Enter</span>
                <button
                  aria-label="Отправить сообщение"
                  className="send-button"
                  disabled={draft.trim().length === 0}
                  type="submit"
                />
              </form>
            ) : (
              <p className="read-only-notice">В этом чате доступно только чтение.</p>
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
    <div className={`message-row${outgoing ? ' outgoing' : ''}`}>
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
    </div>
  );
}

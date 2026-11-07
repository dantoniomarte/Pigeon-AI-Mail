import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';

import {
  ApiError,
  type DraftView,
  type InboxMessage,
  type MessageDetail,
  type SentMessage,
  type SentStatus,
  type Theme,
  deleteDraft,
  demoEnrichment,
  emailAddress,
  fetchDrafts,
  fetchFolder,
  fetchMessage,
  fetchSent,
  patchMessage,
  deleteMessage,
  emptyTrash,
  logout,
  type FolderCounts,
  getStoredFrom,
  getStoredKey,
  storeFrom,
  storeKey,
  textToHtml,
} from './api';
import { LANGUAGE_STORAGE_KEY, detectLanguage, isLanguageCode } from './i18n';
import Compose from './components/Compose';
import AdminPanel from './components/AdminPanel';
import DraftsList from './components/DraftsList';
import MailList, { type MailListItem } from './components/MailList';
import MailView from './components/MailView';
import Settings from './components/Settings';
import Login from './components/Login';
import Setup from './components/Setup';
import { hasSession } from './api';
import Sidebar from './components/Sidebar';
import Toast, { type ToastItem, type ToastKind } from './components/Toast';
import TopBar from './components/TopBar';

export type View = 'inbox' | 'sent' | 'spam' | 'trash' | 'drafts' | 'settings' | 'admin';

export type LoadState = 'idle' | 'loading' | 'ready' | 'error' | 'forbidden';

export interface ComposeSeed {
  from: string;
  to: string;
  /** Prefilled Cc line, when continuing a draft that had one. */
  cc?: string;
  subject: string;
  body: string;
  /** Set when the box was opened from `Drafts`: saves patch this row and sends
   *  go through `POST /v1/drafts/{id}/send`. */
  draftId?: string;
  /** Attachments to restore (already base64, as the API stores them). */
  attachments?: { filename: string; content: string }[];
  tags?: string[];
}

const THEME_STORAGE = 'pigeon_theme';
const MOTION_STORAGE = 'pigeon_motion';
const READ_STORAGE = 'pigeon_read';

function readTheme(): Theme {
  try {
    const stored = localStorage.getItem(THEME_STORAGE);
    if (stored === 'light' || stored === 'dark') {
      return stored;
    }
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  } catch {
    return 'light';
  }
}

function readMotion(): boolean {
  try {
    return localStorage.getItem(MOTION_STORAGE) !== 'off';
  } catch {
    return true;
  }
}

function readReadIds(): Set<string> {
  try {
    const raw = localStorage.getItem(READ_STORAGE);
    if (raw === null) {
      return new Set<string>();
    }
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) {
      return new Set<string>();
    }
    return new Set(parsed.filter((value): value is string => typeof value === 'string'));
  } catch {
    return new Set<string>();
  }
}

function persistReadIds(ids: Set<string>): void {
  try {
    localStorage.setItem(READ_STORAGE, JSON.stringify([...ids].slice(-500)));
  } catch {
    // Storage may be unavailable; unread state simply stays in memory.
  }
}

function emptySeed(): ComposeSeed {
  return { from: getStoredFrom(), to: '', subject: '', body: '' };
}

export default function App(): JSX.Element {
  const { t, i18n: i18nInstance } = useTranslation();

  const [apiKey, setApiKey] = useState<string | null>(() => getStoredKey());
  const [sessionActive, setSessionActive] = useState<boolean>(false);
  const [sessionChecked, setSessionChecked] = useState<boolean>(false);
  const [apiKeyFallback, setApiKeyFallback] = useState<boolean>(false);

  // Resolve the HttpOnly session cookie once on mount (JD-A-003).
  useEffect(() => {
    let cancelled = false;
    void hasSession().then((active) => {
      if (!cancelled) {
        setSessionActive(active);
        setSessionChecked(true);
      }
    });
    return () => {
      cancelled = true;
    };
  }, []);
  const [view, setView] = useState<View>('inbox');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [theme, setTheme] = useState<Theme>(() => readTheme());
  const [motion, setMotion] = useState<boolean>(() => readMotion());
  const [lang, setLang] = useState<string>(() => detectLanguage());
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [composeOpen, setComposeOpen] = useState(false);
  const [composeSeed, setComposeSeed] = useState<ComposeSeed>(() => emptySeed());
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const toastId = useRef(0);

  const [inbox, setInbox] = useState<InboxMessage[]>([]);
  const [sent, setSent] = useState<SentMessage[]>([]);
  const [drafts, setDrafts] = useState<DraftView[]>([]);
  // Drafts are fetched on their own so a failure there is visible in the Drafts
  // view instead of being folded into an empty list.
  const [draftsState, setDraftsState] = useState<LoadState>('idle');
  const [demo, setDemo] = useState(false);
  const [listState, setListState] = useState<LoadState>('idle');
  const [reloadToken, setReloadToken] = useState(0);
  const [counts, setCounts] = useState<FolderCounts | null>(null);
  const activeFolder = view === 'inbox' || view === 'sent' || view === 'spam' || view === 'trash' ? view : null;

  const [detail, setDetail] = useState<MessageDetail | null>(null);
  const [detailState, setDetailState] = useState<LoadState>('idle');
  // Per-message demo flag: a sample read is labelled on its own, so one offline
  // reply never marks every other message as demo content.
  const [detailDemo, setDetailDemo] = useState(false);
  const [detailToken, setDetailToken] = useState(0);
  const [readIds, setReadIds] = useState<Set<string>>(() => readReadIds());

  const notify = useCallback((kind: ToastKind, message: string) => {
    toastId.current += 1;
    const id = toastId.current;
    setToasts((current) => [...current, { id, kind, message }]);
  }, []);

  const dismissToast = useCallback((id: number) => {
    setToasts((current) => current.filter((toast) => toast.id !== id));
  }, []);

  /* Theme, motion and language live on the document root. */
  useEffect(() => {
    document.documentElement.dataset['theme'] = theme;
    try {
      localStorage.setItem(THEME_STORAGE, theme);
    } catch {
      // Ignore storage failures.
    }
    const meta = document.querySelector('meta[name="theme-color"]');
    if (meta !== null) {
      meta.setAttribute('content', theme === 'dark' ? '#0f1117' : '#f8f9fa');
    }
  }, [theme]);

  useEffect(() => {
    document.body.dataset['motion'] = motion ? 'on' : 'off';
    try {
      localStorage.setItem(MOTION_STORAGE, motion ? 'on' : 'off');
    } catch {
      // Ignore storage failures.
    }
  }, [motion]);

  useEffect(() => {
    document.documentElement.lang = lang;
    if (i18nInstance.language !== lang) {
      void i18nInstance.changeLanguage(lang);
    }
    try {
      localStorage.setItem(LANGUAGE_STORAGE_KEY, lang);
    } catch {
      // Ignore storage failures.
    }
  }, [lang, i18nInstance]);

  /* Mailbox data. */
  useEffect(() => {
    if (apiKey === null && !sessionActive) {
      setInbox([]);
      setSent([]);
      setListState('idle');
      return;
    }
    let cancelled = false;
    setListState('loading');
    void Promise.all([
      activeFolder !== null ? fetchFolder(apiKey, activeFolder) : fetchFolder(apiKey, 'inbox'),
      fetchSent(apiKey),
    ])
      .then(([inboxResult, sentResult]) => {
        if (cancelled) {
          return;
        }
        setInbox(inboxResult.data);
        setSent(sentResult.data);
        setDemo(inboxResult.demo || sentResult.demo);
        setListState('ready');
        setCounts(inboxResult.counts ?? null);
      })
      .catch((error: unknown) => {
        if (cancelled) {
          return;
        }
        if (error instanceof ApiError && error.isUnauthorized) {
          // A revoked/typo'd key or an expired session sends the user back
          // to re-auth (Setup for key mode, Login for session mode).
          storeKey(null);
          setApiKey(null);
          setSessionActive(false);
          setApiKeyFallback(false);
          setListState('idle');
          notify('error', i18nInstance.t('auth.unauthorized'));
          return;
        }
        setListState(error instanceof ApiError && error.isForbidden ? 'forbidden' : 'error');
      });
    return () => {
      cancelled = true;
    };
  }, [apiKey, activeFolder, reloadToken, sessionActive, notify, i18nInstance]);

  /* Drafts, fetched separately so their load state can be shown on its own. */
  useEffect(() => {
    if (apiKey === null && !sessionActive) {
      setDrafts([]);
      setDraftsState('idle');
      return;
    }
    let cancelled = false;
    setDraftsState('loading');
    void fetchDrafts(apiKey)
      .then((list) => {
        if (cancelled) {
          return;
        }
        setDrafts(list);
        setDraftsState('ready');
      })
      .catch((error: unknown) => {
        if (cancelled) {
          return;
        }
        setDraftsState(error instanceof ApiError && error.isForbidden ? 'forbidden' : 'error');
      });
    return () => {
      cancelled = true;
    };
  }, [apiKey, reloadToken, sessionActive]);

  /* Selected message body. Sent mail lives on /v1/emails (metadata only). */
  useEffect(() => {
    if ((apiKey === null && !sessionActive) || selectedId === null || view === 'sent') {
      setDetail(null);
      setDetailState('idle');
      return;
    }
    let cancelled = false;
    setDetailState('loading');
    setDetail(null);
    setDetailDemo(false);
    void fetchMessage(apiKey, selectedId)
      .then((result) => {
        if (cancelled) {
          return;
        }
        setDetail(result.data);
        setDetailDemo(result.demo);
        setDetailState('ready');
        setReadIds((current) => {
          if (current.has(selectedId)) {
            return current;
          }
          const next = new Set(current);
          next.add(selectedId);
          persistReadIds(next);
          return next;
        });
      })
      .catch((error: unknown) => {
        if (cancelled) {
          return;
        }
        setDetailState(error instanceof ApiError && error.isForbidden ? 'forbidden' : 'error');
      });
    return () => {
      cancelled = true;
    };
  }, [apiKey, selectedId, detailToken, view, sessionActive]);

  const refresh = useCallback(() => setReloadToken((token) => token + 1), []);

  // These actions only render inside the authenticated mailbox view, where
  // apiKey is non-null; the guard keeps TypeScript honest.
  const key = apiKey ?? '';

  const handleMarkRead = useCallback((id: string, read: boolean) => {
    // Move the local read set with the PATCH: the row loses its bold weight and
    // the unread counter follows immediately, before the mailbox reloads.
    const applyRead = (value: boolean): void => {
      setReadIds((current) => {
        if (current.has(id) === value) {
          return current;
        }
        const next = new Set(current);
        if (value) {
          next.add(id);
        } else {
          next.delete(id);
        }
        persistReadIds(next);
        return next;
      });
    };
    applyRead(read);
    void patchMessage(key, id, { read })
      .then(refresh)
      .catch(() => {
        // The server rejected the change: put the row back where it was.
        applyRead(!read);
        notify('error', t('common.error'));
      });
  }, [key, notify, refresh, t]);

  const handleMove = useCallback((id: string, folder: 'inbox' | 'spam' | 'trash') => {
    void patchMessage(key, id, { folder })
      .then(() => {
        setSelectedId(null);
        refresh();
        notify('success', folder === 'spam' ? t('mail.movedSpam') : folder === 'trash' ? t('mail.movedTrash') : t('mail.movedInbox'));
      })
      .catch(() => notify('error', t('common.error')));
  }, [key, notify, refresh, t]);

  const handleDelete = useCallback((id: string) => {
    void deleteMessage(key, id)
      .then(() => {
        setSelectedId(null);
        refresh();
        notify('success', t('mail.deleted'));
      })
      .catch(() => notify('error', t('common.error')));
  }, [key, notify, refresh, t]);

  const handleEmptyTrash = useCallback(() => {
    void emptyTrash(key)
      .then((deleted: number) => {
        refresh();
        notify('success', t('mail.trashEmptied', { count: deleted }));
      })
      .catch(() => notify('error', t('common.error')));
  }, [key, notify, refresh, t]);

  const items = useMemo<MailListItem[]>(() => {
    if (view === 'sent') {
      return sent.map((message) => ({
        id: message.id,
        from: message.to !== undefined && message.to.length > 0 ? message.to.join(', ') : t('mail.noRecipients'),
        subject: message.subject ?? t('mail.noSubject'),
        createdAt: message.created_at,
        preview: null,
        unread: false,
        encrypted: true,
        status: message.status as SentStatus,
      }));
    }
    return inbox.map((message) => {
      const enrichment = demo ? demoEnrichment(message.id) : null;
      return {
        id: message.id,
        from: message.from_addr,
        subject: message.subject ?? t('mail.noSubject'),
        createdAt: message.created_at ?? null,
        preview: enrichment?.preview ?? null,
        unread: demo ? (enrichment?.unread ?? false) : !readIds.has(message.id),
        encrypted: true,
      };
    });
  }, [view, inbox, sent, demo, readIds, t]);

  const sentSelection = useMemo<SentMessage | null>(() => {
    if (view !== 'sent' || selectedId === null) {
      return null;
    }
    return sent.find((message) => message.id === selectedId) ?? null;
  }, [view, selectedId, sent]);

  const sentDetail = useMemo<MessageDetail | null>(() => {
    if (sentSelection === null) {
      return null;
    }
    return {
      id: sentSelection.id,
      from_addr: sentSelection.from ?? '',
      to: sentSelection.to,
      subject: sentSelection.subject,
      created_at: sentSelection.created_at,
    };
  }, [sentSelection]);

  const unreadCount = useMemo(
    () => inbox.filter((message) => (demo ? (demoEnrichment(message.id)?.unread ?? false) : !readIds.has(message.id))).length,
    [inbox, demo, readIds],
  );

  const handleSignOut = useCallback(() => {
    void logout().catch(() => { /* offline sign-out still completes locally */ });
    storeKey(null);
    setApiKey(null);
    setSelectedId(null);
    setInbox([]);
    setSent([]);
    setDrafts([]);
    setView('inbox');
    setReadIds(new Set<string>());
    setSessionActive(false);
    setApiKeyFallback(false);
    notify('info', t('toast.signedOut'));
  }, [notify, t]);

  const handleSelectView = useCallback((next: View) => {
    setView(next);
    setSidebarOpen(false);
    setSelectedId(null);
  }, []);

  /* The off-canvas sidebar closes on Escape, like any other overlay. */
  useEffect(() => {
    if (!sidebarOpen) {
      return;
    }
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setSidebarOpen(false);
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [sidebarOpen]);

  const startCompose = useCallback(() => {
    setComposeSeed(emptySeed());
    setComposeOpen(true);
  }, []);

  /** Open the compose box on a stored draft. */
  const continueDraft = useCallback((draft: DraftView) => {
    const html = (draft.html ?? '').trim();
    setComposeSeed({
      from: draft.from.trim().length > 0 ? draft.from : getStoredFrom(),
      to: draft.to.join(', '),
      cc: draft.cc.join(', '),
      subject: draft.subject ?? '',
      body: html.length > 0 ? html : textToHtml(draft.text ?? ''),
      draftId: draft.id,
      attachments: draft.attachments.map((file) => ({
        filename: file.filename,
        content: file.content,
      })),
      tags: draft.tags,
    });
    setComposeOpen(true);
  }, []);

  const removeDraft = useCallback(
    (draft: DraftView) => {
      void deleteDraft(key, draft.id)
        .then(() => {
          refresh();
          notify('success', t('drafts.deleted'));
        })
        .catch(() => notify('error', t('common.error')));
    },
    [key, notify, refresh, t],
  );

  const handleReply = useCallback(
    (message: MessageDetail, mode: 'reply' | 'forward') => {
      const sender = emailAddress(message.from_addr);
      const subject = message.subject ?? '';
      const quoted =
        mode === 'forward'
          ? `\n\n---------- ${t('mail.forward')} ----------\n${t('mail.from')}: ${message.from_addr}\n${t('compose.subject')}: ${subject}\n\n${message.body_text ?? ''}`
          : '';
      setComposeSeed({
        from: getStoredFrom(),
        to: mode === 'reply' ? sender : '',
        subject: mode === 'reply' ? (subject.startsWith('Re:') ? subject : `Re: ${subject}`) : subject,
        body: quoted,
      });
      setComposeOpen(true);
    },
    [t],
  );

  // Login FIRST: a fresh visitor without a session sees the Login screen.
  // Setup (API key) is a fallback for headless/agent usage via a link.
  if (!sessionChecked) {
    return <></>; // resolving the session cookie
  }

  if (!sessionActive && !apiKeyFallback) {
    return (
      <Login
        onSuccess={() => {
          setSessionActive(true);
        }}
        onUseApiKey={() => {
          setApiKeyFallback(true);
        }}
      />
    );
  }

  if ((apiKey === null && !sessionActive) || apiKeyFallback) {
    return (
      <Setup
        onReady={(key) => {
          storeKey(key);
          setApiKey(key);
          setApiKeyFallback(false);
        }}
        lang={lang}
        onLangChange={(code) => {
          if (isLanguageCode(code)) {
            setLang(code);
          }
        }}
        theme={theme}
        onToggleTheme={() => setTheme((current) => (current === 'light' ? 'dark' : 'light'))}
        motion={motion}
        onToggleMotion={() => setMotion((current) => !current)}
      />
    );
  }

  // The reading pane only exists for a mail folder: Settings and the Admin
  // console both take the whole workspace.
  const showReading = selectedId !== null && view !== 'settings' && view !== 'admin';

  return (
    <div
      className={`app${showReading ? ' app--reading' : ''}${view === 'drafts' ? ' app--drafts' : ''}`}
    >
      <TopBar
        lang={lang}
        onLangChange={(code) => {
          if (isLanguageCode(code)) {
            setLang(code);
          }
        }}
        theme={theme}
        onToggleTheme={() => setTheme((current) => (current === 'light' ? 'dark' : 'light'))}
        motion={motion}
        onToggleMotion={() => setMotion((current) => !current)}
        onOpenSidebar={() => setSidebarOpen((open) => !open)}
        sidebarOpen={sidebarOpen}
        onCompose={startCompose}
      />

      <span className="app__grain" aria-hidden="true" />

      <main className="shell">
        <Sidebar
          counts={counts}
          view={view}
          unreadCount={unreadCount}
          sentCount={sent.length}
          draftsCount={drafts.length}
          onSelect={handleSelectView}
          onCompose={startCompose}
          open={sidebarOpen}
          apiKey={apiKey}
          onSignOut={handleSignOut}
          onClose={() => setSidebarOpen(false)}
        />

        {view === 'drafts' ? (
          <DraftsList
            drafts={drafts}
            state={draftsState}
            onContinue={continueDraft}
            onDelete={removeDraft}
            onRefresh={refresh}
            onCompose={startCompose}
          />
        ) : view === 'settings' ? (
          <Settings
            apiKey={apiKey}
            lang={lang}
            onLangChange={setLang}
            theme={theme}
            onThemeChange={setTheme}
            motion={motion}
            onMotionChange={setMotion}
            onSignOut={handleSignOut}
            notify={notify}
          />
        ) : view === 'admin' ? (
          <AdminPanel apiKey={apiKey} notify={notify} />
        ) : (
          <>
            <MailList
              view={view}
              items={items}
              state={listState}
              selectedId={selectedId}
              demo={demo}
              counts={counts}
              onMarkRead={handleMarkRead}
              onMove={handleMove}
              onDelete={handleDelete}
              onEmptyTrash={handleEmptyTrash}
              onSelect={setSelectedId}
              onRetry={() => setReloadToken((token) => token + 1)}
              onCompose={startCompose}
            />
            <MailView
              mode={view === 'sent' ? 'sent' : 'mail'}
              message={view === 'sent' ? sentDetail : detail}
              state={view === 'sent' ? (sentSelection !== null ? 'ready' : 'idle') : detailState}
              sentStatus={sentSelection?.status}
              demo={view === 'sent' ? demo : detailDemo}
              onBack={() => setSelectedId(null)}
              onReply={(message) => handleReply(message, 'reply')}
              onForward={(message) => handleReply(message, 'forward')}
              onRetry={() => setDetailToken((token) => token + 1)}
              onMarkRead={handleMarkRead}
              onMove={handleMove}
              onDelete={handleDelete}
            />
          </>
        )}
      </main>

      {composeOpen ? (
        <Compose
          apiKey={apiKey}
          seed={composeSeed}
          onClose={() => setComposeOpen(false)}
          onSent={(from) => {
            storeFrom(from);
            setComposeOpen(false);
            setReloadToken((token) => token + 1);
            notify('success', t('toast.sent'));
          }}
          onDraftSaved={() => setReloadToken((token) => token + 1)}
          notify={notify}
        />
      ) : null}

      <Toast items={toasts} onDismiss={dismissToast} />

      <nav className="mobile-tabs" aria-label={t('nav.mail')}>
        <button
          type="button"
          className={`mobile-tabs__item${view === 'inbox' ? ' is-active' : ''}`}
          onClick={() => handleSelectView('inbox')}
        >
          {t('nav.inbox')}
        </button>
        <button
          type="button"
          className={`mobile-tabs__item${view === 'sent' ? ' is-active' : ''}`}
          onClick={() => handleSelectView('sent')}
        >
          {t('nav.sent')}
        </button>
        <button
          type="button"
          className={`mobile-tabs__item${view === 'settings' ? ' is-active' : ''}`}
          onClick={() => handleSelectView('settings')}
        >
          {t('nav.settings')}
        </button>
        <button
          type="button"
          className="mobile-tabs__item mobile-tabs__item--accent"
          onClick={startCompose}
        >
          {t('nav.compose')}
        </button>
      </nav>
    </div>
  );
}

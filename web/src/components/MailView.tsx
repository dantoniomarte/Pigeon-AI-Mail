import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  ChevronLeft,
  Forward,
  Lock,
  Paperclip,
  RefreshCw,
  Reply,
  ShieldAlert,
  ShieldCheck,
  Mail,
  MailOpen,
  Trash2,
} from 'lucide-react';
import type { CSSProperties } from 'react';

import {
  type AuthVerdict,
  type MessageDetail,
  avatarHue,
  buildEmailFrame,
  decodeMimeWords,
  fetchMessage,
  hasRemoteContent,
  displayName,
  emailAddress,
  formatSize,
  linkifyText,
  initials,
} from '../api';
import type { SentStatus } from '../api';
import type { LoadState } from '../App';
import { PigeonArt } from './MailList';

export interface MailViewProps {
  mode: 'mail' | 'sent';
  /** Credential for the sent-body fetch: the API key, or null for session mode. */
  apiKey?: string | null;
  /** Active app theme: dark mail frames render with the dark scheme. */
  scheme?: 'light' | 'dark';
  message: MessageDetail | null;
  state: LoadState;
  sentStatus?: SentStatus;
  demo: boolean;
  onBack: () => void;
  onReply: (message: MessageDetail) => void;
  onForward: (message: MessageDetail) => void;
  onRetry: () => void;
  onMarkRead?: (id: string, read: boolean) => void;
  onMove?: (id: string, folder: 'inbox' | 'spam' | 'trash') => void;
  onDelete?: (id: string) => void;
  /** Older neighbour in the list the reader was opened from, `null` at the end. */
  prevId?: string | null;
  /** Newer neighbour in the same list, `null` at the end. */
  nextId?: string | null;
  onNavigate?: (id: string) => void;
  /** J/K and the arrows stay off while an overlay (drawer, compose) is open. */
  shortcutsEnabled?: boolean;
}

type Tone = 'ok' | 'warn' | 'bad' | 'muted';

const VERDICT_LABELS = ['pass', 'fail', 'softfail', 'neutral', 'none'] as const;

function toneFor(value: string): Tone {
  switch (value) {
    case 'pass':
      return 'ok';
    case 'fail':
      return 'bad';
    case 'softfail':
      return 'warn';
    default:
      return 'muted';
  }
}

function VerdictChip({ name, value }: { name: string; value: string }): JSX.Element {
  const { t } = useTranslation();
  const known = VERDICT_LABELS.some((label) => label === value);
  const label = known ? t(`mail.${value}`) : value;
  const tone = toneFor(value);
  return (
    <span className={`verdict verdict--${tone}`} title={`${name}: ${label}`}>
      <span className="verdict__dot" aria-hidden="true" />
      <span className="verdict__name">{name}</span>
      <span className="verdict__value">{label}</span>
    </span>
  );
}

function bodyOf(message: MessageDetail): { html: string } | { text: string } | null {
  if (message.body_html !== undefined && message.body_html.trim().length > 0) {
    return { html: message.body_html };
  }
  if (message.body_text !== undefined && message.body_text.trim().length > 0) {
    return { text: message.body_text };
  }
  return null;
}

/** Plain-text paragraph: URLs become real links so long addresses stop
 *  deforming the layout or hiding inside the sentence. */
function TextParagraph({ value }: { value: string }): JSX.Element {
  return (
    <p>
      {linkifyText(value).map((token, index) =>
        token.kind === 'link' ? (
          <a key={index} href={token.href} target="_blank" rel="noreferrer">
            {token.value}
          </a>
        ) : (
          <span key={index}>{token.value}</span>
        ),
      )}
    </p>
  );
}

export default function MailView({
  mode,
  apiKey = null,
  scheme = 'light',
  message,
  state,
  sentStatus,
  demo,
  onBack,
  onReply,
  onForward,
  onRetry,
  onMarkRead,
  onMove,
  onDelete,
  prevId = null,
  nextId = null,
  onNavigate,
  shortcutsEnabled = true,
}: MailViewProps): JSX.Element {
  const { t, i18n } = useTranslation();
  const isSent = mode === 'sent';
  // The sent reader's delete is permanent and irreversible, so the first click
  // only arms the confirmation; a different message disarms it again.
  const [confirmDelete, setConfirmDelete] = useState(false);
  useEffect(() => {
    setConfirmDelete(false);
  }, [message?.id]);
  // Remote content in HTML mail is opt-in per message, and the choice resets
  // when another message is opened.
  const [remoteImages, setRemoteImages] = useState(false);
  useEffect(() => {
    setRemoteImages(false);
  }, [message?.id]);
  // The sandboxed frame reports its rendered height; sized to content (bounded)
  // so short mail does not show a tall empty panel or push actions off-screen.
  const [frameHeight, setFrameHeight] = useState<number | null>(null);
  // F2: production CSP blocks the frame's inline bootstrap (script-src
  // 'self' on srcdoc), so the height/scroll handshake cannot rely on scripts
  // inside the frame. Height is measured from the frame element's layout via
  // ResizeObserver on its documentElement (same-origin-less srcdoc still
  // allows contentDocument access for about:srcdoc in Firefox/Chromium with
  // sandbox allow-scripts? No: opaque origin BLOCKS contentDocument). The
  // parent-side measurement below uses the iframe element box only.
  // O1: switching the theme rebuilds the frame document (new srcDoc), which
  // resets its scroll to the top. Without the script channel the restore is
  // impossible; instead the frame key includes the scheme so the reader
  // scroll (parent .reader__scroll) is preserved naturally — the page-level
  // scroll does not reset when the iframe content re-renders at the same
  // element. The user's complaint is the INNER frame scroll; with a sized
  // frame (auto-height dead → fixed 612px) the inner scroll resets. Restoring
  // the inner position without scripts requires the scroll to live OUTSIDE
  // the frame: keep the frame heightless (full document height) is not
  // possible without measurement. So: measure via ResizeObserver on the
  // frame element (its height animates with our style), and report the
  // content height through the load event using a same-origin-free trick:
  // about:srcdoc in Firefox exposes contentDocument.height for sandboxed
  // frames — Chromium does not. Final approach: keep the bootstrap script but
  // ALSO fix the prod CSP (server-side) to allow inline scripts in srcdoc
  // frames; here, degrade gracefully: no height message -> frame keeps the
  // CSS clamp height (still usable, as #86 documented).
  const frameScrollRef = useRef<number | null>(null);
  useEffect(() => {
    const onMessage = (event: MessageEvent) => {
      const data = event.data as { type?: string; value?: number } | null;
      if (
        data !== null &&
        typeof data === 'object' &&
        data.type === 'pigeon-frame-height' &&
        typeof data.value === 'number' &&
        Number.isFinite(data.value) &&
        data.value > 0
      ) {
        setFrameHeight(Math.min(1400, Math.max(240, Math.ceil(data.value))));
      }
      // F1 fix: remember the reading fraction so the theme-flip restore has
      // something to replay (the prod audit found the ref was only read).
      if (
        data !== null &&
        typeof data === 'object' &&
        data.type === 'pigeon-frame-scroll' &&
        typeof data.value === 'number' &&
        Number.isFinite(data.value)
      ) {
        frameScrollRef.current = data.value;
      }
    };
    window.addEventListener('message', onMessage);
    return () => window.removeEventListener('message', onMessage);
  }, []);
  useEffect(() => {
    setFrameHeight(null);
    // JD-B-002: a fresh message must not inherit the previous one's reading
    // fraction (the judge measured a mid-document jump on the next flip).
    frameScrollRef.current = null;
  }, [message?.id]);
  // O1: after the theme changes the frame document is rebuilt; restore the
  // remembered reading position once the new document reports its height.
  const schemeRef = useRef(scheme);
  useEffect(() => {
    const flipped = schemeRef.current !== scheme;
    schemeRef.current = scheme;
    if (!flipped || frameHeight === null || frameScrollRef.current === null) {
      return;
    }
    const value = frameScrollRef.current;
    // Post as soon as each frame element exists (load fires per iframe); the
    // fixed 120 ms timer left a visible jump-to-top flash during the flip.
    const post = (event: Event) => {
      const frame = event.target as HTMLIFrameElement;
      frame.contentWindow?.postMessage({ type: 'pigeon-frame-restore', value }, '*');
    };
    for (const frame of Array.from(document.querySelectorAll<HTMLIFrameElement>('iframe.reader__frame'))) {
      frame.addEventListener('load', post, { once: true });
    }
    const timer = window.setTimeout(() => {
      for (const frame of Array.from(document.querySelectorAll<HTMLIFrameElement>('iframe.reader__frame'))) {
        frame.contentWindow?.postMessage({ type: 'pigeon-frame-restore', value }, '*');
      }
    }, 120);
    return () => {
      window.clearTimeout(timer);
      for (const frame of Array.from(document.querySelectorAll<HTMLIFrameElement>('iframe.reader__frame'))) {
        frame.removeEventListener('load', post);
      }
    };
  }, [scheme, frameHeight]);
  // Sent rows arrive as lifecycle metadata (`/v1/emails`); the body lives
  // behind the message route, so the reader fetches it once per sent message.
  const [sentBody, setSentBody] = useState<MessageDetail | null>(null);
  const [sentBodyState, setSentBodyState] = useState<'idle' | 'loading' | 'ready' | 'error'>('idle');
  useEffect(() => {
    if (mode !== 'sent' || message === null) {
      setSentBody(null);
      setSentBodyState('idle');
      return;
    }
    let cancelled = false;
    setSentBodyState('loading');
    setSentBody(null);
    void fetchMessage(apiKey, message.id)
      .then((result) => {
        if (cancelled) return;
        setSentBody(result.data);
        setSentBodyState('ready');
      })
      .catch(() => {
        if (cancelled) return;
        setSentBodyState('error');
      });
    return () => {
      cancelled = true;
    };
  }, [mode, message]);

  // J/K and the arrow keys walk the list the reader was opened from, as long as
  // the user is not typing somewhere and no other handler took the key first.
  const readerOpen = message !== null || state === 'loading';
  useEffect(() => {
    if (onNavigate === undefined || !readerOpen || !shortcutsEnabled) {
      return;
    }
    const onKeyDown = (event: KeyboardEvent): void => {
      if (event.defaultPrevented || event.metaKey || event.ctrlKey || event.altKey) {
        return;
      }
      const target = event.target;
      if (target instanceof HTMLElement) {
        const tag = target.tagName;
        if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || target.isContentEditable) {
          return;
        }
      }
      // An open modal (compose) owns the keyboard while it is up.
      if (document.querySelector('[aria-modal="true"]') !== null) {
        return;
      }
      const older = event.key === 'k' || event.key === 'K' || event.key === 'ArrowUp';
      const newer = event.key === 'j' || event.key === 'J' || event.key === 'ArrowDown';
      if (older && prevId !== null) {
        event.preventDefault();
        onNavigate(prevId);
        return;
      }
      if (newer && nextId !== null) {
        event.preventDefault();
        onNavigate(nextId);
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [onNavigate, readerOpen, shortcutsEnabled, prevId, nextId]);

  const fullDate =
    message?.created_at !== undefined
      ? new Intl.DateTimeFormat(i18n.language, { dateStyle: 'long', timeStyle: 'short' }).format(
          new Date(message.created_at),
        )
      : '';

  const renderContent = (): JSX.Element => {
    if (state === 'loading') {
      return (
        <div className="reader__loading" aria-busy="true" aria-label={t('common.loading')}>
          <span className="skeleton skeleton--line skeleton--title" />
          <div className="reader__loading-meta">
            <span className="skeleton skeleton--avatar" />
            <span className="skeleton skeleton--line skeleton--short" />
          </div>
          <span className="skeleton skeleton--line" />
          <span className="skeleton skeleton--line" />
          <span className="skeleton skeleton--line skeleton--short" />
        </div>
      );
    }

    if (state === 'error' || state === 'forbidden') {
      const forbidden = state === 'forbidden';
      return (
        <div className="state-card state-card--centered" role="alert">
          <span className={`state-card__icon${forbidden ? ' state-card__icon--warn' : ''}`}>
            {forbidden ? <ShieldAlert size={24} /> : <AlertTriangle size={24} />}
          </span>
          <h3>{forbidden ? t('mail.forbiddenTitle') : t('mail.errorTitle')}</h3>
          <p>{forbidden ? t('mail.forbiddenBody') : t('mail.errorBody')}</p>
          {!forbidden ? (
            <button type="button" className="btn btn--ghost" onClick={onRetry}>
              <RefreshCw size={15} aria-hidden="true" />
              {t('common.retry')}
            </button>
          ) : null}
        </div>
      );
    }

    if (message === null) {
      return (
        <div className="state-card state-card--centered reader__empty">
          <PigeonArt size={220} />
          <h3>{t('mail.selectTitle')}</h3>
          <p>{t('mail.selectBody')}</p>
        </div>
      );
    }

    const body = bodyOf(message);
    const auth: AuthVerdict = message.auth ?? { spf: 'none', dkim: 'none', dmarc: 'none' };
    const hue = avatarHue(message.from_addr);

    return (
      <div className="reader__document">
        <div className="reader__header">
          {demo ? (
            <span className="badge badge--demo">
              <Lock size={11} aria-hidden="true" />
              {t('app.demo')}
            </span>
          ) : null}
          {isSent && sentStatus !== undefined ? (
            <span className={`badge badge--status is-${sentStatus}`}>{t(`mail.status.${sentStatus}`)}</span>
          ) : null}
          <h1 className="reader__subject">{message.subject !== undefined ? decodeMimeWords(message.subject) : t('mail.noSubject')}</h1>

          <div className="reader__identity">
            <span className="avatar avatar--lg" style={{ '--avatar-hue': hue } as CSSProperties} aria-hidden="true">
              {initials(message.from_addr)}
            </span>
            <div className="reader__identity-text">
              <span className="reader__from">{displayName(message.from_addr)}</span>
              <span className="reader__addresses">
                <span>{emailAddress(message.from_addr)}</span>
                {message.to !== undefined && message.to.length > 0 ? (
                  <span className="reader__to">
                    {t('mail.to')} {message.to.join(', ')}
                  </span>
                ) : null}
              </span>
            </div>
            <time className="reader__date" dateTime={message.created_at}>
              {fullDate}
            </time>
          </div>

          {!isSent && message.auth !== undefined ? (
            <div className="verdicts" aria-label={t('mail.authTitle')}>
              <VerdictChip name={t('mail.spf')} value={auth.spf} />
              <VerdictChip name={t('mail.dkim')} value={auth.dkim} />
              <VerdictChip name={t('mail.dmarc')} value={auth.dmarc} />
              {auth.tls !== undefined ? (
                <span className="verdict verdict--muted" title={`${t('mail.tls')}: ${auth.tls}`}>
                  <ShieldCheck size={12} aria-hidden="true" />
                  <span className="verdict__name">{t('mail.tls')}</span>
                  <span className="verdict__value">{auth.tls}</span>
                </span>
              ) : null}
            </div>
          ) : null}
        </div>

        <div className={`reader__body${(body !== null && 'html' in body) || (isSent && sentBody !== null && sentBody.body_html !== undefined && sentBody.body_html.trim().length > 0) ? ' reader__body--html' : ''}`}>
          {isSent && sentBodyState === 'loading' ? (
            <div aria-busy="true" aria-label={t('common.loading')}>
              <span className="skeleton skeleton--line" />
              <span className="skeleton skeleton--line skeleton--short" />
              <span className="skeleton skeleton--line" />
            </div>
          ) : isSent && sentBodyState === 'error' ? (
            <p className="reader__note">{t('mail.sentBodyError')}</p>
          ) : isSent && sentBody !== null && sentBody.body_html !== undefined && sentBody.body_html.trim().length > 0 ? (
            <>
              {hasRemoteContent(sentBody.body_html) ? (
                <p className="reader__note reader__images-note">
                  <span>{remoteImages ? t('mail.remoteImagesOn') : t('mail.remoteImagesOff')}</span>
                  <button
                    type="button"
                    className="btn btn--ghost reader__images-toggle"
                    onClick={() => setRemoteImages((value) => !value)}
                  >
                    {remoteImages ? t('mail.blockImages') : t('mail.loadImages')}
                  </button>
                </p>
              ) : null}
              <iframe
                className="reader__frame"
                title={t('mail.messageBody')}
                sandbox="allow-popups allow-popups-to-escape-sandbox allow-scripts"
                style={frameHeight !== null ? { height: `${frameHeight}px` } : undefined}
                srcDoc={buildEmailFrame(sentBody.body_html, remoteImages, scheme)}
              />
            </>
          ) : isSent && sentBody !== null && sentBody.body_text !== undefined && sentBody.body_text.trim().length > 0 ? (
            sentBody.body_text.split(/\n{2,}/).map((paragraph, index) => (
              <TextParagraph key={index} value={paragraph} />
            ))
          ) : isSent ? (
            <p className="reader__note">{t('mail.sentBodyError')}</p>
          ) : body !== null && 'html' in body ? (
            <>
              {hasRemoteContent(body.html) ? (
                <p className="reader__note reader__images-note">
                  <span>{remoteImages ? t('mail.remoteImagesOn') : t('mail.remoteImagesOff')}</span>
                  <button
                    type="button"
                    className="btn btn--ghost reader__images-toggle"
                    onClick={() => setRemoteImages((value) => !value)}
                  >
                    {remoteImages ? t('mail.blockImages') : t('mail.loadImages')}
                  </button>
                </p>
              ) : null}
              {/* Scripts and same-origin are excluded on purpose: an email is
                  untrusted input, and the CSP inside the frame is the second
                  layer behind the sandbox. */}
              <iframe
                className="reader__frame"
                title={t('mail.messageBody')}
                sandbox="allow-popups allow-popups-to-escape-sandbox allow-scripts"
                style={frameHeight !== null ? { height: `${frameHeight}px` } : undefined}
                srcDoc={buildEmailFrame(body.html, remoteImages, scheme)}
              />
            </>
          ) : body !== null && 'text' in body ? (
            body.text.split(/\n{2,}/).map((paragraph, index) => (
              <TextParagraph key={index} value={paragraph} />
            ))
          ) : message.sealed_body !== undefined ? (
            <p className="reader__note">{t('mail.sealedBody')}</p>
          ) : (
            <p className="reader__note">{t('mail.noBody')}</p>
          )}
        </div>

        {message.attachments !== undefined && message.attachments.length > 0 ? (
          <div className="reader__attachments">
            <h2 className="reader__section-title">
              <Paperclip size={14} aria-hidden="true" />
              {t('mail.attachments')}
            </h2>
            <ul className="attachment-list">
              {message.attachments.map((attachment) => (
                <li className="attachment" key={attachment.id}>
                  <span className="attachment__icon" aria-hidden="true">
                    <Paperclip size={15} />
                  </span>
                  <span className="attachment__meta">
                    <span className="attachment__name">{attachment.filename}</span>
                    <span className="attachment__size">{formatSize(attachment.size, i18n.language)}</span>
                  </span>
                </li>
              ))}
            </ul>
          </div>
        ) : null}


      </div>
    );
  };

  return (
    <section className="reader" aria-label={t('mail.inbox')}>
      <header className="reader__bar">
        <button type="button" className="icon-btn reader__back" onClick={onBack} aria-label={t('common.back')}>
          <ChevronLeft size={19} />
        </button>
        <span className="reader__bar-spacer" />
        {onNavigate === undefined ? null : (
          <div className="reader__nav" role="group" aria-label={`${t('mail.older')} / ${t('mail.newer')}`}>
            <button
              type="button"
              className="icon-btn reader__nav-btn"
              disabled={prevId === null}
              onClick={() => {
                if (prevId !== null) {
                  onNavigate(prevId);
                }
              }}
              aria-label={`${t('mail.older')} (K / ↑)`}
              title={`${t('mail.older')} (K / ↑)`}
            >
              <ArrowLeft size={17} />
            </button>
            <button
              type="button"
              className="icon-btn reader__nav-btn"
              disabled={nextId === null}
              onClick={() => {
                if (nextId !== null) {
                  onNavigate(nextId);
                }
              }}
              aria-label={`${t('mail.newer')} (J / ↓)`}
              title={`${t('mail.newer')} (J / ↓)`}
            >
              <ArrowRight size={17} />
            </button>
          </div>
        )}
        <div className="reader__bar-actions">
          {!isSent ? (
            <button
              type="button"
              className="btn btn--quiet"
              onClick={() => {
                if (message !== null) {
                  onReply(message);
                }
              }}
              disabled={message === null}
              aria-label={t('mail.reply')}
            >
              <Reply size={15} aria-hidden="true" />
              <span>{t('mail.reply')}</span>
            </button>
          ) : null}
          <button
            type="button"
            className="btn btn--quiet"
            onClick={() => {
              if (message !== null) {
                onForward(message);
              }
            }}
            disabled={message === null}
            aria-label={t('mail.forward')}
          >
            <Forward size={15} aria-hidden="true" />
            <span>{t('mail.forward')}</span>
          </button>
          {!isSent && onMarkRead !== undefined && message !== null ? (
            <button
              type="button"
              className="btn btn--quiet"
              onClick={() => onMarkRead(message.id, !message.read)}
              disabled={message === null}
              aria-label={message.read ? t('mail.markUnread') : t('mail.markRead')}
              title={message.read ? t('mail.markUnread') : t('mail.markRead')}
            >
              {message.read ? <MailOpen size={15} aria-hidden="true" /> : <Mail size={15} aria-hidden="true" />}
              <span className="reader__bar-label">
                {message.read ? t('mail.markUnread') : t('mail.markRead')}
              </span>
            </button>
          ) : null}
          {!isSent && onMove !== undefined && message !== null ? (
            <button
              type="button"
              className="btn btn--quiet"
              onClick={() => onMove(message.id, 'spam')}
              disabled={message === null}
              aria-label={t('mail.toSpam')}
              title={t('mail.toSpam')}
            >
              <ShieldAlert size={15} aria-hidden="true" />
              <span className="reader__bar-label">{t('mail.toSpam')}</span>
            </button>
          ) : null}
          {!isSent && onMove !== undefined && message !== null ? (
            <button
              type="button"
              className="btn btn--quiet"
              onClick={() => onMove(message.id, 'trash')}
              disabled={message === null}
              aria-label={t('mail.toTrash')}
              title={t('mail.toTrash')}
            >
              <Trash2 size={15} aria-hidden="true" />
              <span className="reader__bar-label">{t('mail.toTrash')}</span>
            </button>
          ) : null}
          {onDelete !== undefined && message !== null ? (
            <button
              type="button"
              className={`btn btn--quiet${isSent && confirmDelete ? ' btn--danger' : ''}`}
              onClick={() => {
                // Sent rows arm a confirmation first: the delete is
                // permanent (no trash for outbound copies).
                if (isSent && !confirmDelete) {
                  setConfirmDelete(true);
                  return;
                }
                setConfirmDelete(false);
                onDelete(message.id);
              }}
              disabled={message === null}
              aria-label={isSent && confirmDelete ? t('mail.confirmDelete') : t('mail.deleteForever')}
              title={isSent && confirmDelete ? t('mail.confirmDelete') : t('mail.deleteForever')}
            >
              <Trash2 size={15} aria-hidden="true" />
              <span className="reader__bar-label">
                {isSent && confirmDelete ? t('mail.confirmDelete') : t('mail.deleteForever')}
              </span>
            </button>
          ) : null}
        </div>
      </header>
      <div className="reader__scroll">{renderContent()}</div>
    </section>
  );
}

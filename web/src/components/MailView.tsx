import { useTranslation } from 'react-i18next';
import {
  AlertTriangle,
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
  X,
} from 'lucide-react';
import type { CSSProperties } from 'react';

import {
  type AuthVerdict,
  type MessageDetail,
  avatarHue,
  displayName,
  emailAddress,
  formatSize,
  htmlToText,
  initials,
} from '../api';
import type { SentStatus } from '../api';
import type { LoadState } from '../App';
import { PigeonArt } from './MailList';

export interface MailViewProps {
  mode: 'mail' | 'sent';
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

function bodyOf(message: MessageDetail): { text: string; fromHtml: boolean } | null {
  if (message.body_text !== undefined && message.body_text.trim().length > 0) {
    return { text: message.body_text, fromHtml: false };
  }
  if (message.body_html !== undefined && message.body_html.trim().length > 0) {
    const extracted = htmlToText(message.body_html);
    if (extracted.length > 0) {
      return { text: extracted, fromHtml: true };
    }
  }
  return null;
}

export default function MailView({
  mode,
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
}: MailViewProps): JSX.Element {
  const { t, i18n } = useTranslation();
  const isSent = mode === 'sent';

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
          <h1 className="reader__subject">{message.subject ?? t('mail.noSubject')}</h1>

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

        <div className="reader__body">
          {isSent ? (
            <p className="reader__note">{t('mail.sentNote')}</p>
          ) : body !== null ? (
            <>
              {body.fromHtml ? <p className="reader__note">{t('mail.htmlOnly')}</p> : null}
              {body.text.split(/\n{2,}/).map((paragraph, index) => (
                <p key={index}>{paragraph}</p>
              ))}
            </>
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

        {isSent ? null : (
          <div className="reader__actions">
            <button type="button" className="btn btn--primary" onClick={() => onReply(message)}>
              <Reply size={16} aria-hidden="true" />
              {t('mail.reply')}
            </button>
            <button type="button" className="btn btn--ghost" onClick={() => onForward(message)}>
              <Forward size={16} aria-hidden="true" />
              {t('mail.forward')}
            </button>
            {onMarkRead ? (
              <button
                type="button"
                className="btn btn--ghost"
                onClick={() => onMarkRead(message.id, !message.read)}
                aria-label={message.read ? t('mail.markUnread') : t('mail.markRead')}
                title={message.read ? t('mail.markUnread') : t('mail.markRead')}
              >
                {message.read ? <MailOpen size={16} aria-hidden="true" /> : <Mail size={16} aria-hidden="true" />}
              </button>
            ) : null}
            {onMove ? (
              <button
                type="button"
                className="btn btn--ghost"
                onClick={() => onMove(message.id, 'spam')}
                aria-label={t('mail.toSpam')}
                title={t('mail.toSpam')}
              >
                <ShieldAlert size={16} aria-hidden="true" />
              </button>
            ) : null}
            {onMove ? (
              <button
                type="button"
                className="btn btn--ghost"
                onClick={() => onMove(message.id, 'trash')}
                aria-label={t('mail.toTrash')}
                title={t('mail.toTrash')}
              >
                <Trash2 size={16} aria-hidden="true" />
              </button>
            ) : null}
            {onDelete ? (
              <button
                type="button"
                className="btn btn--ghost reader__delete"
                onClick={() => onDelete(message.id)}
                aria-label={t('mail.deleteForever')}
                title={t('mail.deleteForever')}
              >
                <X size={16} aria-hidden="true" />
              </button>
            ) : null}
          </div>
        )}
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
        {isSent ? null : (
          <div className="reader__bar-actions">
            <button
              type="button"
              className="btn btn--quiet"
              onClick={() => {
                if (message !== null) {
                  onReply(message);
                }
              }}
              disabled={message === null}
            >
              <Reply size={15} aria-hidden="true" />
              <span>{t('mail.reply')}</span>
            </button>
            <button
              type="button"
              className="btn btn--quiet"
              onClick={() => {
                if (message !== null) {
                  onForward(message);
                }
              }}
              disabled={message === null}
            >
              <Forward size={15} aria-hidden="true" />
              <span>{t('mail.forward')}</span>
            </button>
          </div>
        )}
      </header>
      <div className="reader__scroll">{renderContent()}</div>
    </section>
  );
}

import {  useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  AlertTriangle,
  Lock,
  Mail,
  MailOpen,
  RefreshCw,
  Search,
  ShieldAlert,
  Trash2,
  X,
} from 'lucide-react';

import { avatarHue, displayName, initials, type FolderCounts, type SentStatus } from '../api';
import type { LoadState, View } from '../App';
import type { CSSProperties } from 'react';

export interface MailListItem {
  id: string;
  from: string;
  subject: string;
  createdAt: string | null;
  preview: string | null;
  unread: boolean;
  encrypted: boolean;
  status?: SentStatus;
}

export interface MailListProps {
  view: Exclude<View, 'settings'>;
  items: MailListItem[];
  state: LoadState;
  selectedId: string | null;
  demo: boolean;
  counts?: FolderCounts | null;
  onMarkRead?: (id: string, read: boolean) => void;
  onMove?: (id: string, folder: 'inbox' | 'spam' | 'trash') => void;
  onDelete?: (id: string) => void;
  onEmptyTrash?: () => void;
  onSelect: (id: string) => void;
  onRetry: () => void;
  onCompose: () => void;
}

type MailFilter = 'all' | 'unread';

interface Group {
  key: string;
  label: string;
  items: MailListItem[];
}

/** Decorative pigeon-and-envelope illustration used by every empty state. */
export function PigeonArt({ size = 200 }: { size?: number }): JSX.Element {
  return (
    <svg
      viewBox="0 0 220 170"
      width={size}
      height={(size * 170) / 220}
      className="art"
      aria-hidden="true"
      focusable="false"
    >
      <defs>
        <linearGradient id="pigeonArtGlow" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="var(--accent)" stopOpacity="0.26" />
          <stop offset="1" stopColor="var(--enc)" stopOpacity="0.12" />
        </linearGradient>
      </defs>
      <circle cx="110" cy="82" r="66" fill="url(#pigeonArtGlow)" />
      <circle cx="110" cy="82" r="66" fill="none" stroke="var(--border)" strokeDasharray="2 7" />
      <rect x="58" y="86" width="104" height="62" rx="12" fill="var(--surface)" stroke="var(--border-strong)" />
      <path d="M60 97l50 33 50-33" fill="none" stroke="var(--border-strong)" strokeWidth="2" />
      <ellipse cx="112" cy="72" rx="26" ry="16" fill="var(--accent)" />
      <circle cx="136" cy="58" r="12" fill="var(--accent)" />
      <path d="M147 55l13 5-13 6z" fill="var(--warn)" />
      <circle cx="140" cy="55" r="2" fill="#fff" />
      <path
        d="M88 70c8-14 20-19 34-16-6 3-10 7-12 12 8-1 14 1 19 6-11-3-19-1-24 5-6 7-14 5-17-7z"
        fill="#fff"
        opacity="0.2"
      />
      <path d="M44 64h14M40 77h10" stroke="var(--accent)" strokeWidth="2" strokeLinecap="round" opacity="0.5" />
    </svg>
  );
}

function startOfDay(date: Date): number {
  return new Date(date.getFullYear(), date.getMonth(), date.getDate()).getTime();
}

export default function MailList({
  view,
  items,
  state,
  selectedId,
  demo,
  counts,
  onMarkRead,
  onMove,
  onDelete,
  onEmptyTrash,
  onSelect,
  onRetry,
  onCompose,
}: MailListProps): JSX.Element {
  const { t, i18n } = useTranslation();
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState<MailFilter>('all');

  const timeFormat = useMemo(
    () => new Intl.DateTimeFormat(i18n.language, { hour: '2-digit', minute: '2-digit' }),
    [i18n.language],
  );
  const dateFormat = useMemo(
    () => new Intl.DateTimeFormat(i18n.language, { month: 'short', day: 'numeric' }),
    [i18n.language],
  );
  const fullFormat = useMemo(
    () => new Intl.DateTimeFormat(i18n.language, { dateStyle: 'medium', timeStyle: 'short' }),
    [i18n.language],
  );

  const visible = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return items.filter((item) => {
      if (filter === 'unread' && !item.unread) {
        return false;
      }
      if (needle.length === 0) {
        return true;
      }
      return (
        item.from.toLowerCase().includes(needle) ||
        item.subject.toLowerCase().includes(needle) ||
        (item.preview ?? '').toLowerCase().includes(needle)
      );
    });
  }, [items, query, filter]);

  const groups = useMemo<Group[]>(() => {
    const today = startOfDay(new Date());
    const yesterday = today - 86_400_000;
    const buckets: Group[] = [
      { key: 'today', label: t('mail.today'), items: [] },
      { key: 'yesterday', label: t('mail.yesterday'), items: [] },
      { key: 'earlier', label: t('mail.earlier'), items: [] },
    ];
    for (const item of visible) {
      const parsed = item.createdAt === null ? null : new Date(item.createdAt);
      const stamp = parsed !== null && !Number.isNaN(parsed.getTime()) ? startOfDay(parsed) : null;
      const bucket = stamp === null ? buckets[2] : stamp === today ? buckets[0] : stamp === yesterday ? buckets[1] : buckets[2];
      bucket?.items.push(item);
    }
    return buckets.filter((bucket) => bucket.items.length > 0);
  }, [visible, t]);

  const emptyCopy = useMemo(() => {
    switch (view) {
      case 'sent':
        return { title: t('mail.emptySentTitle'), body: t('mail.emptySentBody') };
      case 'spam':
        return { title: t('mail.emptySpamTitle'), body: t('mail.emptySpamBody') };
      case 'trash':
        return { title: t('mail.emptyTrashTitle'), body: t('mail.emptyTrashBody') };
      default:
        return { title: t('mail.emptyInboxTitle'), body: t('mail.emptyInboxBody') };
    }
  }, [t, view]);

  const title =
    view === 'sent'
      ? t('mail.sent')
      : view === 'spam'
        ? t('nav.spam')
        : view === 'trash'
          ? t('nav.trash')
          : t('mail.inbox');
  const unreadTotal = items.filter((item) => item.unread).length;
  // The inbox header counts what is unread, not the size of the folder.
  const countLabel =
    view === 'sent'
      ? t('mail.count', { count: items.length })
      : t('mail.unreadCount', { count: unreadTotal });
  const spamCount = counts !== undefined && counts !== null && view === 'inbox' && counts.spam > 0
    ? t('mail.spamCount', { count: counts.spam })
    : null;

  const stamp = (createdAt: string | null): string => {
    if (createdAt === null) {
      return '';
    }
    const parsed = new Date(createdAt);
    if (Number.isNaN(parsed.getTime())) {
      return '';
    }
    return startOfDay(parsed) === startOfDay(new Date())
      ? timeFormat.format(parsed)
      : dateFormat.format(parsed);
  };

  const fullStamp = (createdAt: string | null): string => {
    if (createdAt === null) {
      return '';
    }
    const parsed = new Date(createdAt);
    return Number.isNaN(parsed.getTime()) ? '' : fullFormat.format(parsed);
  };

  const renderState = (): JSX.Element | null => {
    if (state === 'loading' || state === 'idle') {
      return (
        <div className="mail-list__skeletons" aria-busy="true" aria-label={t('common.loading')}>
          {Array.from({ length: 7 }, (_, index) => (
            <div className="skeleton-row" key={index}>
              <span className="skeleton skeleton--avatar" />
              <span className="skeleton-row__lines">
                <span className="skeleton skeleton--line skeleton--short" />
                <span className="skeleton skeleton--line" />
                <span className="skeleton skeleton--line skeleton--tiny" />
              </span>
            </div>
          ))}
        </div>
      );
    }
    if (state === 'error' || state === 'forbidden') {
      const forbidden = state === 'forbidden';
      return (
        <div className="state-card state-card--compact" role="alert">
          <span className={`state-card__icon${forbidden ? ' state-card__icon--warn' : ''}`}>
            {forbidden ? <ShieldAlert size={22} /> : <AlertTriangle size={22} />}
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
    if (visible.length === 0) {
      const searching = query.trim().length > 0;
      return (
        <div className="state-card">
          <PigeonArt size={190} />
          <h3>{searching ? t('mail.emptySearchTitle') : emptyCopy.title}</h3>
          <p>{searching ? t('mail.emptySearchBody') : emptyCopy.body}</p>
          {!searching && view === 'inbox' ? (
            <button type="button" className="btn btn--primary" onClick={onCompose}>
              {t('nav.compose')}
            </button>
          ) : null}
        </div>
      );
    }
    return null;
  };

  const stateContent = renderState();

  return (
    <section className="mail-list" aria-label={title}>
      <header className="mail-list__head">
        <div className="mail-list__title">
          <h2>{title}</h2>
          <span className="mail-list__count">
            {countLabel}
            {spamCount !== null ? ` · ${spamCount}` : ''}
          </span>
        </div>
        <div className="mail-list__tools">
          {view === 'trash' && onEmptyTrash ? (
            <button
              type="button"
              className="icon-btn"
              onClick={onEmptyTrash}
              aria-label={t('mail.emptyTrash')}
              title={t('mail.emptyTrash')}
            >
              <Trash2 size={16} />
            </button>
          ) : null}
          <button
            type="button"
            className="icon-btn"
            onClick={onRetry}
            aria-label={t('common.refresh')}
            title={t('common.refresh')}
          >
            <RefreshCw size={16} />
          </button>
        </div>
        <div className="mail-list__search">
          <Search size={15} aria-hidden="true" className="mail-list__search-icon" />
          <input
            type="search"
            value={query}
            placeholder={t('mail.searchPlaceholder')}
            aria-label={t('common.search')}
            onChange={(event) => setQuery(event.target.value)}
          />
          {query.length > 0 ? (
            <button
              type="button"
              className="mail-list__search-clear"
              onClick={() => setQuery('')}
              aria-label={t('common.close')}
            >
              <X size={14} />
            </button>
          ) : null}
        </div>
        {view === 'inbox' ? (
          <div className="segmented" role="group" aria-label={t('mail.all')}>
            <button
              type="button"
              aria-pressed={filter === 'all'}
              className={`segmented__item${filter === 'all' ? ' is-active' : ''}`}
              onClick={() => setFilter('all')}
            >
              {t('mail.all')}
            </button>
            <button
              type="button"
              aria-pressed={filter === 'unread'}
              className={`segmented__item${filter === 'unread' ? ' is-active' : ''}`}
              onClick={() => setFilter('unread')}
            >
              {t('mail.unread')}
            </button>
          </div>
        ) : null}
      </header>

      {demo ? <p className="demo-banner">{t('mail.demoBanner')}</p> : null}

      <div className="mail-list__scroll">
        {stateContent ?? (
          <div className="mail-list__groups">
            {groups.map((group) => (
              <div className="mail-group" key={group.key}>
                <p className="mail-group__label">{group.label}</p>
                <ul className="mail-group__list">
                  {group.items.map((item) => {
                    const hue = avatarHue(item.from);
                    const selected = item.id === selectedId;
                    return (
                      <li key={item.id}>
                        <button
                          type="button"
                          className={`mail-row${selected ? ' is-selected' : ''}${item.unread ? ' is-unread' : ''}`}
                          onClick={() => onSelect(item.id)}
                          aria-current={selected ? 'true' : undefined}
                        >
                          <span
                            className="avatar"
                            style={{ '--avatar-hue': hue } as CSSProperties}
                            aria-hidden="true"
                          >
                            {initials(item.from)}
                          </span>
                          <span className="mail-row__content">
                            <span className="mail-row__top">
                              <span className="mail-row__from">{displayName(item.from)}</span>
                              <span className="mail-row__time" title={fullStamp(item.createdAt)}>
                                {stamp(item.createdAt)}
                              </span>
                            </span>
                            <span className="mail-row__subject">{item.subject}</span>
                            <span className="mail-row__preview">
                              {item.preview ?? (item.encrypted ? t('mail.previewLocked') : '')}
                            </span>
                            <span className="mail-row__badges">
                              {item.encrypted ? (
                                <span className="badge badge--enc">
                                  <Lock size={11} aria-hidden="true" />
                                  {t('mail.encrypted')}
                                </span>
                              ) : null}
                              {item.status !== undefined ? (
                                <span className={`badge badge--status is-${item.status}`}>
                                  {t(`mail.status.${item.status}`)}
                                </span>
                              ) : null}
                              {item.unread ? (
                                <span
                                  className="mail-row__unread-dot"
                                  role="img"
                                  aria-label={t('mail.unreadDot')}
                                />
                              ) : null}
                            </span>
                          </span>
                        </button>
                        {(onMarkRead || onMove || onDelete) && view !== 'sent' ? (
                          <span className="mail-row__actions">
                            {onMarkRead ? (
                              <button
                                type="button"
                                tabIndex={selected ? 0 : -1}
                                className="row-action"
                                onClick={(event) => {
                                  event.stopPropagation();
                                  onMarkRead(item.id, !item.unread);
                                }}
                                aria-label={item.unread ? t('mail.markRead') : t('mail.markUnread')}
                                title={item.unread ? t('mail.markRead') : t('mail.markUnread')}
                              >
                                {item.unread ? <MailOpen size={14} /> : <Mail size={14} />}
                              </button>
                            ) : null}
                            {onMove && view !== 'spam' ? (
                              <button
                                type="button"
                                tabIndex={selected ? 0 : -1}
                                className="row-action"
                                onClick={(event) => {
                                  event.stopPropagation();
                                  onMove(item.id, 'spam');
                                }}
                                aria-label={t('mail.toSpam')}
                                title={t('mail.toSpam')}
                              >
                                <ShieldAlert size={14} />
                              </button>
                            ) : null}
                            {onMove && view !== 'trash' ? (
                              <button
                                type="button"
                                tabIndex={selected ? 0 : -1}
                                className="row-action"
                                onClick={(event) => {
                                  event.stopPropagation();
                                  onMove(item.id, 'trash');
                                }}
                                aria-label={t('mail.toTrash')}
                                title={t('mail.toTrash')}
                              >
                                <Trash2 size={14} />
                              </button>
                            ) : null}
                            {onDelete ? (
                              <button
                                type="button"
                                tabIndex={selected ? 0 : -1}
                                className="row-action row-action--danger"
                                onClick={(event) => {
                                  event.stopPropagation();
                                  onDelete(item.id);
                                }}
                                aria-label={t('mail.deleteForever')}
                                title={t('mail.deleteForever')}
                              >
                                <X size={14} />
                              </button>
                            ) : null}
                          </span>
                        ) : null}
                      </li>
                    );
                  })}
                </ul>
              </div>
            ))}
          </div>
        )}
      </div>
    </section>
  );
}

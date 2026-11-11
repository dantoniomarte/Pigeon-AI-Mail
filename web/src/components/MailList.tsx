import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
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
import { deriveActiveIds, remainingSelection, type BulkOutcome } from '../bulk';
import type { LoadState, View } from '../App';
import BulkBar from './BulkBar';
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
  /** The shared address (alias or catch-all) this copy arrived for, when it did. */
  deliveredFor?: string;
}

/** One selectable "Delivered to" value with the inbox count behind it. */
export interface DeliveredOption {
  address: string;
  count: number;
}

export interface MailListProps {
  view: Exclude<View, 'settings'>;
  items: MailListItem[];
  state: LoadState;
  selectedId: string | null;
  demo: boolean;
  counts?: FolderCounts | null;
  /** Inbox counts per shared address: one pseudo-folder per alias/catch-all. */
  deliveredOptions?: DeliveredOption[];
  /** Active "Delivered to" filter, `null` for the whole folder. */
  deliveredFilter?: string | null;
  onDeliveredFilter?: (address: string | null) => void;
  onMarkRead?: (id: string, read: boolean) => void;
  onMove?: (id: string, folder: 'inbox' | 'spam' | 'trash') => void;
  onDelete?: (id: string) => void;
  /** Bulk variants: the same per-message endpoints, applied to a whole selection.
   *  Each resolves with what the server accepted, so the selection can keep the
   *  ids that failed. */
  onMarkReadBulk?: (ids: string[], read: boolean) => Promise<BulkOutcome>;
  onMoveBulk?: (ids: string[], folder: 'inbox' | 'spam' | 'trash') => Promise<BulkOutcome>;
  onDeleteBulk?: (ids: string[]) => Promise<BulkOutcome>;
  onEmptyTrash?: () => void;
  onSelect: (id: string) => void;
  /** Reports the ids on screen, in display order, so the reader can walk the
   *  very same list without refetching anything. */
  onVisibleIds?: (ids: string[]) => void;
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
  deliveredOptions,
  deliveredFilter,
  onDeliveredFilter,
  onMarkRead,
  onMove,
  onDelete,
  onMarkReadBulk,
  onMoveBulk,
  onDeleteBulk,
  onEmptyTrash,
  onSelect,
  onVisibleIds,
  onRetry,
  onCompose,
}: MailListProps): JSX.Element {
  const { t, i18n } = useTranslation();
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState<MailFilter>('all');
  const [selectedIds, setSelectedIds] = useState<Set<string>>(() => new Set<string>());
  const [bulkBusy, setBulkBusy] = useState(false);
  // Two-step confirm, like the drafts list: a bulk delete is irreversible.
  const [confirmDelete, setConfirmDelete] = useState(false);
  const masterRef = useRef<HTMLInputElement | null>(null);
  // Sent mail is metadata-only on /v1/emails: the PATCH/DELETE message routes
  // would 404 there, so bulk actions only exist for the mailbox folders.
  // Sent mail participates in bulk deletion only (the backend accepts the eml_
  // id on the delete route); read/spam/trash bulk actions stay mailbox-only.
  const bulkEnabled =
    (view !== 'sent' || onDeleteBulk !== undefined) &&
    (onMarkReadBulk !== undefined || onMoveBulk !== undefined || onDeleteBulk !== undefined);

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

  /* Selection ------------------------------------------------------ */
  const visibleIds = useMemo(() => visible.map((item) => item.id), [visible]);
  // Only ids that are still on screen count: a row hidden by the unread filter
  // or the search box must not be modified behind the user's back.
  const activeIds = useMemo(() => deriveActiveIds(visibleIds, selectedIds), [visibleIds, selectedIds]);
  const allVisibleSelected = visibleIds.length > 0 && activeIds.length === visibleIds.length;
  const someVisibleSelected = activeIds.length > 0 && !allVisibleSelected;
  const masterLabel = allVisibleSelected
    ? t('mail.deselectAll')
    : activeIds.length > 0
      ? t('mail.selectedCount', { count: activeIds.length })
      : t('mail.selectAll');

  // A different folder or filter is a different set of rows.
  useEffect(() => {
    setSelectedIds((current) => (current.size === 0 ? current : new Set<string>()));
    setConfirmDelete(false);
  }, [view, filter, deliveredFilter]);

  // `indeterminate` is a DOM property only, so it needs a ref.
  useEffect(() => {
    if (masterRef.current !== null) {
      masterRef.current.indeterminate = someVisibleSelected;
    }
  }, [someVisibleSelected]);

  const reportVisibleIds = useRef(onVisibleIds);
  useEffect(() => {
    reportVisibleIds.current = onVisibleIds;
  }, [onVisibleIds]);
  useEffect(() => {
    reportVisibleIds.current?.(visibleIds);
  }, [visibleIds]);

  const toggleOne = useCallback((id: string, next: boolean) => {
    setSelectedIds((current) => {
      const copy = new Set(current);
      if (next) {
        copy.add(id);
      } else {
        copy.delete(id);
      }
      return copy;
    });
    setConfirmDelete(false);
  }, []);

  const toggleAllVisible = useCallback(() => {
    setSelectedIds((current) => {
      const copy = new Set(current);
      const everyVisible = visibleIds.length > 0 && visibleIds.every((id) => current.has(id));
      for (const id of visibleIds) {
        if (everyVisible) {
          copy.delete(id);
        } else {
          copy.add(id);
        }
      }
      return copy;
    });
    setConfirmDelete(false);
  }, [visibleIds]);

  const clearSelection = useCallback(() => {
    setSelectedIds(new Set<string>());
    setConfirmDelete(false);
  }, []);

  const runBulkAction = useCallback(
    async (action: (ids: string[]) => Promise<BulkOutcome>): Promise<void> => {
      if (activeIds.length === 0 || bulkBusy) {
        return;
      }
      const snapshot = [...activeIds];
      setBulkBusy(true);
      try {
        const outcome = await action(snapshot);
        // Only accepted ids leave the selection: a failed id stays checked (all
        // of them when nothing succeeded) so the retry is one click away.
        setSelectedIds((current) => remainingSelection(current, outcome.applied));
      } finally {
        setBulkBusy(false);
        setConfirmDelete(false);
      }
    },
    [activeIds, bulkBusy],
  );

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
          {bulkEnabled ? (
            <label className="check-all" title={masterLabel}>
              <input
                ref={masterRef}
                type="checkbox"
                className="checkbox"
                checked={allVisibleSelected}
                disabled={visibleIds.length === 0}
                aria-label={masterLabel}
                onChange={toggleAllVisible}
              />
            </label>
          ) : null}
          <h2>{title}</h2>
          <span className="mail-list__count">
            {countLabel}
            {spamCount !== null ? ` · ${spamCount}` : ''}
          </span>
          {/* Always mounted: a live region announced only when it appears is
              silent in most screen readers. */}
          <span className="sr-only" aria-live="polite" aria-atomic="true">
            {activeIds.length > 0 ? t('mail.selectedCount', { count: activeIds.length }) : ''}
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
        {activeIds.length > 0 ? (
          <BulkBar
            count={activeIds.length}
            busy={bulkBusy}
            confirmDelete={confirmDelete}
            canMarkRead={onMarkReadBulk !== undefined && view !== 'sent'}
            canSpam={onMoveBulk !== undefined && view !== 'sent' && view !== 'spam'}
            canTrash={onMoveBulk !== undefined && view !== 'sent' && view !== 'trash'}
            canDelete={onDeleteBulk !== undefined}
            onMarkRead={(read) => {
              if (onMarkReadBulk === undefined) {
                return;
              }
              void runBulkAction((ids) => onMarkReadBulk(ids, read));
            }}
            onMove={(folder) => {
              if (onMoveBulk === undefined) {
                return;
              }
              void runBulkAction((ids) => onMoveBulk(ids, folder));
            }}
            onDelete={() => {
              // First click arms the confirmation, the second one really deletes.
              if (!confirmDelete) {
                setConfirmDelete(true);
                return;
              }
              if (onDeleteBulk === undefined) {
                return;
              }
              void runBulkAction((ids) => onDeleteBulk(ids));
            }}
            onClear={clearSelection}
          />
        ) : (
          <>
            {view === 'inbox' &&
            deliveredOptions !== undefined &&
            (deliveredOptions.length > 0 || (deliveredFilter ?? null) !== null) ? (
              <label className="mail-list__delivered">
                <span className="segmented__label">{t('mail.deliveredTo')}</span>
                <select
                  className="input input--small"
                  value={deliveredFilter ?? ''}
                  onChange={(event) =>
                    onDeliveredFilter?.(event.target.value.length > 0 ? event.target.value : null)
                  }
                >
                  <option value="">{t('mail.deliveredAll')}</option>
                  {deliveredOptions.map((option) => (
                    <option key={option.address} value={option.address}>
                      {t('mail.deliveredOption', { address: option.address, count: option.count })}
                    </option>
                  ))}
                </select>
              </label>
            ) : null}
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
          </>
        )}
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
                    const checked = selectedIds.has(item.id);
                    return (
                      <li key={item.id} className={checked ? 'is-checked' : undefined}>
                        {bulkEnabled ? (
                          <span className="mail-row__select">
                            <input
                              type="checkbox"
                              className="checkbox"
                              checked={checked}
                              aria-label={`${displayName(item.from)}: ${item.subject}`}
                              onChange={(event) => toggleOne(item.id, event.target.checked)}
                              onClick={(event) => event.stopPropagation()}
                              onKeyDown={(event) => {
                                // Space is native; Enter has to toggle by hand.
                                if (event.key === 'Enter') {
                                  event.preventDefault();
                                  toggleOne(item.id, !checked);
                                }
                              }}
                            />
                          </span>
                        ) : null}
                        <button
                          type="button"
                          className={`mail-row${bulkEnabled ? ' mail-row--selectable' : ''}${selected ? ' is-selected' : ''}${item.unread ? ' is-unread' : ''}`}
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
                              {item.deliveredFor !== undefined ? (
                                <span
                                  className="badge badge--muted"
                                  title={t('mail.deliveredFor', { address: item.deliveredFor })}
                                >
                                  {t('mail.deliveredForShort', { address: item.deliveredFor })}
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
                        {(view !== 'sent' && (onMarkRead || onMove || onDelete)) || (view === 'sent' && onDelete) ? (
                          <span className="mail-row__actions">
                            {onMarkRead && view !== 'sent' ? (
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
                            {onMove && view !== 'sent' && view !== 'spam' ? (
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
                            {onMove && view !== 'sent' && view !== 'trash' ? (
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

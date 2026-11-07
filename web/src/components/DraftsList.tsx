import { useCallback, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { AlertTriangle, FileText, PencilLine, RefreshCw, Trash2 } from 'lucide-react';

import type { LoadState } from '../App';
import type { DraftView } from '../api';
import { PigeonArt } from './MailList';

export interface DraftsListProps {
  drafts: DraftView[];
  state: LoadState;
  /** Opens the compose box seeded with this draft. */
  onContinue: (draft: DraftView) => void;
  onDelete: (draft: DraftView) => void;
  onRefresh: () => void;
  onCompose: () => void;
}

/** `Intl.RelativeTimeFormat` buckets, largest unit first. */
const RELATIVE_UNITS: ReadonlyArray<{ unit: Intl.RelativeTimeFormatUnit; seconds: number }> = [
  { unit: 'day', seconds: 86_400 },
  { unit: 'hour', seconds: 3_600 },
  { unit: 'minute', seconds: 60 },
];

/**
 * "Saved 3 minutes ago", localized. Anything older than a week falls back to an
 * absolute date: "saved 23 days ago" is less useful than the date it was saved.
 */
function relativeSaved(savedAt: string, language: string): string {
  const parsed = new Date(savedAt);
  if (Number.isNaN(parsed.getTime())) {
    return '';
  }
  const elapsedSeconds = Math.round((parsed.getTime() - Date.now()) / 1000);
  const absolute = Math.abs(elapsedSeconds);
  const format = new Intl.RelativeTimeFormat(language, { numeric: 'auto' });
  for (const { unit, seconds } of RELATIVE_UNITS) {
    if (absolute >= seconds) {
      return format.format(Math.round(elapsedSeconds / seconds), unit);
    }
  }
  return new Intl.DateTimeFormat(language, { dateStyle: 'medium' }).format(parsed);
}

/** `to` recipients of a draft, or a readable placeholder. */
function recipients(draft: DraftView, emptyLabel: string): string {
  const all = [...draft.to, ...draft.cc, ...draft.bcc];
  return all.length > 0 ? all.join(', ') : emptyLabel;
}

export default function DraftsList({
  drafts,
  state,
  onContinue,
  onDelete,
  onRefresh,
  onCompose,
}: DraftsListProps): JSX.Element {
  const { t, i18n } = useTranslation();
  const [confirmingId, setConfirmingId] = useState<string | null>(null);

  const stamps = useMemo(
    () => new Map(drafts.map((draft) => [draft.id, relativeSaved(draft.updated_at, i18n.language)])),
    [drafts, i18n.language],
  );

  const remove = useCallback(
    (draft: DraftView) => {
      // Two-step delete: a draft may be the only copy of something half-written.
      if (confirmingId === draft.id) {
        setConfirmingId(null);
        onDelete(draft);
        return;
      }
      setConfirmingId(draft.id);
    },
    [confirmingId, onDelete],
  );

  const body = (): JSX.Element => {
    if (state === 'loading' || state === 'idle') {
      return (
        <div className="mail-list__skeletons" aria-busy="true" aria-label={t('common.loading')}>
          {Array.from({ length: 4 }, (_, index) => (
            <div className="skeleton-row" key={index}>
              <span className="skeleton-row__lines">
                <span className="skeleton skeleton--line skeleton--short" />
                <span className="skeleton skeleton--line" />
              </span>
            </div>
          ))}
        </div>
      );
    }
    if (state === 'error' || state === 'forbidden') {
      return (
        <div className="state-card state-card--compact" role="alert">
          <span className="state-card__icon state-card__icon--warn">
            <AlertTriangle size={22} />
          </span>
          <h3>{t('mail.errorTitle')}</h3>
          <p>{t('mail.errorBody')}</p>
          <button type="button" className="btn btn--ghost" onClick={onRefresh}>
            <RefreshCw size={15} aria-hidden="true" />
            {t('common.retry')}
          </button>
        </div>
      );
    }
    if (drafts.length === 0) {
      return (
        <div className="state-card">
          <PigeonArt size={190} />
          <h3>{t('drafts.empty')}</h3>
          <button type="button" className="btn btn--primary" onClick={onCompose}>
            {t('nav.compose')}
          </button>
        </div>
      );
    }
    return (
      <ul className="draft-list">
        {drafts.map((draft) => {
          const confirming = confirmingId === draft.id;
          return (
            <li className="draft-row" key={draft.id}>
              <span className="draft-row__glyph" aria-hidden="true">
                <FileText size={16} />
              </span>
              <div className="draft-row__main">
                <b className="draft-row__subject">{draft.subject ?? t('drafts.noSubject')}</b>
                <span className="draft-row__recipients" title={recipients(draft, t('mail.noRecipients'))}>
                  {recipients(draft, t('mail.noRecipients'))}
                </span>
              </div>
              <span className="draft-row__time">{stamps.get(draft.id) ?? ''}</span>
              <div className="draft-row__actions">
                <button
                  type="button"
                  className="btn btn--ghost btn--small"
                  onClick={() => onContinue(draft)}
                >
                  <PencilLine size={13} aria-hidden="true" />
                  {t('drafts.continue')}
                </button>
                <button
                  type="button"
                  className={`btn btn--ghost btn--small${confirming ? ' btn--danger' : ''}`}
                  onClick={() => remove(draft)}
                  aria-label={`${t('drafts.delete')}: ${draft.subject ?? t('drafts.noSubject')}`}
                >
                  <Trash2 size={13} aria-hidden="true" />
                  {confirming ? t('drafts.confirmDelete') : t('drafts.delete')}
                </button>
              </div>
            </li>
          );
        })}
      </ul>
    );
  };

  return (
    <section className="mail-list" aria-label={t('drafts.title')}>
      <header className="mail-list__head">
        <div className="mail-list__title">
          <h2>{t('drafts.title')}</h2>
          <span className="mail-list__count">{t('mail.count', { count: drafts.length })}</span>
        </div>
        <div className="mail-list__tools">
          <button
            type="button"
            className="icon-btn"
            onClick={onRefresh}
            aria-label={t('common.refresh')}
            title={t('common.refresh')}
          >
            <RefreshCw size={16} />
          </button>
        </div>
      </header>
      <div className="mail-list__scroll">{body()}</div>
    </section>
  );
}

import {
  Archive,
  CircleX,
  Mail,
  MailOpen,
  ShieldAlert,
  Trash2,
  X,
} from 'lucide-react';
import { useTranslation } from 'react-i18next';

export interface BulkBarProps {
  /** How many rows will be acted on. */
  count: number;
  /** A bulk request is in flight: every action is disabled. */
  busy: boolean;
  /** The delete button is armed and waits for its confirmation click. */
  confirmDelete: boolean;
  canMarkRead: boolean;
  canSpam: boolean;
  canTrash: boolean;
  canDelete: boolean;
  /** Offer the folder/selection backup download (eml/mbox). */
  canExport: boolean;
  onMarkRead: (read: boolean) => void;
  onMove: (folder: 'spam' | 'trash') => void;
  onDelete: () => void;
  /** Download one client-side mbox archive of the selected messages. */
  onExport: () => void;
  onClear: () => void;
}

/**
 * The bar that replaces the folder filter while a selection is live. It is
 * purely presentational: MailList owns the selection and the in-flight state.
 */
export default function BulkBar({
  count,
  busy,
  confirmDelete,
  canMarkRead,
  canSpam,
  canTrash,
  canDelete,
  canExport,
  onMarkRead,
  onMove,
  onDelete,
  onExport,
  onClear,
}: BulkBarProps): JSX.Element {
  const { t } = useTranslation();
  const label = t('mail.selectedCount', { count });

  return (
    <div className="bulk-bar" role="group" aria-label={label}>
      <span className="bulk-bar__count">{label}</span>
      <div className="bulk-bar__actions">
        {canMarkRead ? (
          <>
            <button
              type="button"
              className="btn btn--ghost btn--small"
              disabled={busy}
              onClick={() => onMarkRead(true)}
              aria-label={t('mail.markReadBulk')}
              title={t('mail.markReadBulk')}
            >
              <MailOpen size={14} aria-hidden="true" />
              <span>{t('mail.markReadBulk')}</span>
            </button>
            <button
              type="button"
              className="btn btn--ghost btn--small"
              disabled={busy}
              onClick={() => onMarkRead(false)}
              aria-label={t('mail.markUnreadBulk')}
              title={t('mail.markUnreadBulk')}
            >
              <Mail size={14} aria-hidden="true" />
              <span>{t('mail.markUnreadBulk')}</span>
            </button>
          </>
        ) : null}
        {canSpam ? (
          <button
            type="button"
            className="btn btn--ghost btn--small"
            disabled={busy}
            onClick={() => onMove('spam')}
            aria-label={t('mail.spamBulk')}
            title={t('mail.spamBulk')}
          >
            <ShieldAlert size={14} aria-hidden="true" />
            <span>{t('mail.spamBulk')}</span>
          </button>
        ) : null}
        {canTrash ? (
          <button
            type="button"
            className="btn btn--ghost btn--small"
            disabled={busy}
            onClick={() => onMove('trash')}
            aria-label={t('mail.trashBulk')}
            title={t('mail.trashBulk')}
          >
            <Trash2 size={14} aria-hidden="true" />
            <span>{t('mail.trashBulk')}</span>
          </button>
        ) : null}
        {canExport ? (
          <button
            type="button"
            className="btn btn--ghost btn--small"
            disabled={busy}
            onClick={onExport}
            aria-label={t('mail.exportSelection')}
            title={t('mail.exportSelection')}
          >
            <Archive size={14} aria-hidden="true" />
            <span>{t('mail.exportSelection')}</span>
          </button>
        ) : null}
        {canDelete ? (
          <button
            type="button"
            className={`btn btn--small ${confirmDelete ? 'btn--danger' : 'btn--ghost'}`}
            disabled={busy}
            onClick={onDelete}
            aria-label={
              confirmDelete ? t('mail.bulkConfirmDelete', { count }) : t('mail.deleteBulk')
            }
            title={confirmDelete ? t('mail.bulkConfirmDelete', { count }) : t('mail.deleteBulk')}
          >
            <X size={14} aria-hidden="true" />
            <span>
              {confirmDelete ? t('mail.bulkConfirmDelete', { count }) : t('mail.deleteBulk')}
            </span>
          </button>
        ) : null}
        <button
          type="button"
          className="btn btn--quiet btn--small bulk-bar__clear"
          disabled={busy}
          onClick={onClear}
          aria-label={t('mail.clearSelection')}
          title={t('mail.clearSelection')}
        >
          <CircleX size={14} aria-hidden="true" />
          <span>{t('mail.clearSelection')}</span>
        </button>
      </div>
    </div>
  );
}

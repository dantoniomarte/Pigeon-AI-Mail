import { useTranslation } from 'react-i18next';
import {
  FileText,
  Inbox,
  LogOut,
  PenLine,
  Send,
  Settings as SettingsIcon,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  X,
} from 'lucide-react';

import { maskKey, type FolderCounts } from '../api';
import type { View } from '../App';
import { PigeonLogo } from './TopBar';

export interface SidebarProps {
  view: View;
  unreadCount: number;
  sentCount: number;
  /** Saved drafts, shown as a badge like the other folders. */
  draftsCount: number;
  counts?: FolderCounts | null;
  onSelect: (view: View) => void;
  onCompose: () => void;
  open: boolean;
  apiKey: string;
  onSignOut: () => void;
  onClose: () => void;
}

export default function Sidebar({
  view,
  unreadCount,
  sentCount,
  draftsCount,
  counts,
  onSelect,
  onCompose,
  open,
  apiKey,
  onSignOut,
  onClose,
}: SidebarProps): JSX.Element {
  const { t } = useTranslation();

  return (
    <>
      <button
        type="button"
        className={`scrim${open ? ' is-open' : ''}`}
        onClick={onClose}
        aria-label={t('common.closeMenu')}
        tabIndex={open ? 0 : -1}
      />
      <aside className={`sidebar${open ? ' is-open' : ''}`} aria-label={t('nav.mail')}>
        <div className="sidebar__head">
          <button type="button" className="icon-btn sidebar__close" onClick={onClose} aria-label={t('common.close')}>
            <X size={18} />
          </button>
          <button type="button" className="compose-btn" onClick={onCompose}>
            <PenLine size={17} aria-hidden="true" />
            <span>{t('nav.compose')}</span>
          </button>
        </div>

        <nav className="nav">
          <p className="nav__label">{t('nav.mail')}</p>
          <button
            type="button"
            className={`nav__item${view === 'inbox' ? ' is-active' : ''}`}
            onClick={() => onSelect('inbox')}
            aria-current={view === 'inbox' ? 'page' : undefined}
          >
            <Inbox size={18} aria-hidden="true" />
            <span className="nav__text">{t('nav.inbox')}</span>
            {unreadCount > 0 ? <span className="nav__count">{unreadCount}</span> : null}
          </button>
          <button
            type="button"
            className={`nav__item${view === 'sent' ? ' is-active' : ''}`}
            onClick={() => onSelect('sent')}
            aria-current={view === 'sent' ? 'page' : undefined}
          >
            <Send size={18} aria-hidden="true" />
            <span className="nav__text">{t('nav.sent')}</span>
            {sentCount > 0 ? <span className="nav__count nav__count--muted">{sentCount}</span> : null}
          </button>
          <button
            type="button"
            className={`nav__item${view === 'drafts' ? ' is-active' : ''}`}
            onClick={() => onSelect('drafts')}
            aria-current={view === 'drafts' ? 'page' : undefined}
          >
            <FileText size={18} aria-hidden="true" />
            <span className="nav__text">{t('nav.drafts')}</span>
            {draftsCount > 0 ? <span className="nav__count nav__count--muted">{draftsCount}</span> : null}
          </button>
          <button
            type="button"
            className={`nav__item${view === 'spam' ? ' is-active' : ''}`}
            onClick={() => onSelect('spam')}
            aria-current={view === 'spam' ? 'page' : undefined}
          >
            <ShieldAlert size={18} aria-hidden="true" />
            <span className="nav__text">{t('nav.spam')}</span>
            {counts && counts.spam > 0 ? <span className="nav__count">{counts.spam}</span> : null}
          </button>
          <button
            type="button"
            className={`nav__item${view === 'trash' ? ' is-active' : ''}`}
            onClick={() => onSelect('trash')}
            aria-current={view === 'trash' ? 'page' : undefined}
          >
            <Trash2 size={18} aria-hidden="true" />
            <span className="nav__text">{t('nav.trash')}</span>
            {counts && counts.trash > 0 ? <span className="nav__count">{counts.trash}</span> : null}
          </button>

          <p className="nav__label">{t('nav.workspace')}</p>
          {/* Always shown: the API answers 403 for a plain member, and the panel
              says so — hiding the entry would mean nobody discovers it. */}
          <button
            type="button"
            className={`nav__item${view === 'admin' ? ' is-active' : ''}`}
            onClick={() => onSelect('admin')}
            aria-current={view === 'admin' ? 'page' : undefined}
          >
            <ShieldCheck size={18} aria-hidden="true" />
            <span className="nav__text">{t('nav.admin')}</span>
          </button>
          <button
            type="button"
            className={`nav__item${view === 'settings' ? ' is-active' : ''}`}
            onClick={() => onSelect('settings')}
            aria-current={view === 'settings' ? 'page' : undefined}
          >
            <SettingsIcon size={18} aria-hidden="true" />
            <span className="nav__text">{t('nav.settings')}</span>
          </button>
        </nav>

        <div className="sidebar__footer">
          <div className="account">
            <span className="account__mark" aria-hidden="true">
              <PigeonLogo size={22} />
            </span>
            <div className="account__meta">
              <span className="account__title">{t('nav.connected')}</span>
              <code className="account__key" title={t('auth.storedLocally')}>
                {maskKey(apiKey)}
              </code>
            </div>
          </div>
          <button type="button" className="btn btn--ghost btn--block" onClick={onSignOut}>
            <LogOut size={15} aria-hidden="true" />
            {t('common.signOut')}
          </button>
        </div>
      </aside>
    </>
  );
}

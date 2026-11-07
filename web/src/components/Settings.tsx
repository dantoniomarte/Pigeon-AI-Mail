import { useCallback, useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  AlertTriangle,
  Check,
  Copy,
  KeyRound,
  Loader2,
  LogOut,
  Lock,
  Moon,
  Plus,
  RefreshCw,
  ShieldAlert,
  SlidersHorizontal,
  Sun,
  Trash2,
  Webhook as WebhookIcon,
} from 'lucide-react';

import {
  ApiError,
  WEBHOOK_EVENTS,
  createApiKey,
  createWebhook,
  deleteWebhook,
  fetchApiKeys,
  fetchSent,
  fetchWebhooks,
  revokeApiKey,
  type ApiKeyView,
  type Scope,
  type SentMessage,
  type Theme,
  type WebhookEvent,
  type WebhookView,
} from '../api';
import type { LoadState } from '../App';
import { LanguageSelect, MotionSwitch } from './TopBar';
import { DomainsPanel, SuppressionsPanel, TemplatesPanel } from './ManagementPanels';
import { SecurityPanel } from './SecurityPanel';
import type { ToastKind } from './Toast';

export interface SettingsProps {
  apiKey: string | null;
  lang: string;
  onLangChange: (lang: string) => void;
  theme: Theme;
  onThemeChange: (theme: Theme) => void;
  motion: boolean;
  onMotionChange: (motion: boolean) => void;
  onSignOut: () => void;
  notify: (kind: ToastKind, message: string) => void;
}

type Tab = 'overview' | 'keys' | 'webhooks' | 'templates' | 'domains' | 'suppressions' | 'security' | 'preferences';

/** Roving order of the tablist, matching the buttons rendered below. */
const TAB_ORDER: readonly Tab[] = [
  'overview',
  'keys',
  'webhooks',
  'preferences',
  'templates',
  'domains',
  'suppressions',
  'security',
];

const SCOPES: readonly Scope[] = ['send', 'read', 'full'];

const SCOPE_LABELS: Record<Scope, string> = {
  send: 'settings.scopeSend',
  read: 'settings.scopeRead',
  full: 'settings.scopeFull',
};

export default function Settings({
  apiKey,
  lang,
  onLangChange,
  theme,
  onThemeChange,
  motion,
  onMotionChange,
  onSignOut,
  notify,
}: SettingsProps): JSX.Element {
  const { t, i18n } = useTranslation();
  const [tab, setTab] = useState<Tab>('keys');

  /* Arrow keys move between tabs (WAI-ARIA tabs pattern); focus follows the
     selection so the roving tabindex stays reachable from the keyboard. */
  const onTabKeyDown = useCallback(
    (event: React.KeyboardEvent<HTMLDivElement>) => {
      const step = event.key === 'ArrowRight' ? 1 : event.key === 'ArrowLeft' ? -1 : 0;
      if (step === 0) {
        return;
      }
      event.preventDefault();
      const current = TAB_ORDER.indexOf(tab);
      const next = TAB_ORDER[(current + step + TAB_ORDER.length) % TAB_ORDER.length];
      if (next === undefined) {
        return;
      }
      setTab(next);
      document.getElementById(`settings-tab-${next}`)?.focus();
    },
    [tab],
  );

  const [keys, setKeys] = useState<ApiKeyView[]>([]);
  const [keysState, setKeysState] = useState<LoadState>('idle');
  const [keysToken, setKeysToken] = useState(0);

  const [webhooks, setWebhooks] = useState<WebhookView[]>([]);
  const [webhooksState, setWebhooksState] = useState<LoadState>('idle');
  const [webhooksToken, setWebhooksToken] = useState(0);

  const [sentStats, setSentStats] = useState<SentMessage[]>([]);
  const [sentStatsState, setSentStatsState] = useState<LoadState>('idle');

  const [keyName, setKeyName] = useState('');
  const [scopes, setScopes] = useState<Set<Scope>>(() => new Set<Scope>(['read']));
  const [sandbox, setSandbox] = useState(false);
  const [creatingKey, setCreatingKey] = useState(false);
  const [createdKey, setCreatedKey] = useState<string | null>(null);
  const [keysError, setKeysError] = useState<string | null>(null);
  const [pendingRevoke, setPendingRevoke] = useState<string | null>(null);
  const [busyKey, setBusyKey] = useState<string | null>(null);

  const [webhookUrl, setWebhookUrl] = useState('');
  const [webhookEvents, setWebhookEvents] = useState<Set<WebhookEvent>>(
    () => new Set<WebhookEvent>(['email.delivered', 'email.bounced']),
  );
  const [creatingWebhook, setCreatingWebhook] = useState(false);
  const [createdSecret, setCreatedSecret] = useState<string | null>(null);
  const [webhooksError, setWebhooksError] = useState<string | null>(null);
  const [pendingDelete, setPendingDelete] = useState<string | null>(null);
  const [busyWebhook, setBusyWebhook] = useState<string | null>(null);

  useEffect(() => {
    if (tab !== 'keys') {
      return;
    }
    let cancelled = false;
    setKeysState('loading');
    void fetchApiKeys(apiKey)
      .then((list) => {
        if (cancelled) {
          return;
        }
        setKeys(list);
        setKeysState('ready');
      })
      .catch((error: unknown) => {
        if (cancelled) {
          return;
        }
        setKeysState(error instanceof ApiError && error.isForbidden ? 'forbidden' : 'error');
      });
    return () => {
      cancelled = true;
    };
  }, [apiKey, tab, keysToken]);

  // Overview: fetch sent emails to compute stats + volume chart.
  useEffect(() => {
    if (tab !== 'overview') {
      return;
    }
    let cancelled = false;
    setSentStatsState('loading');
    void fetchSent(apiKey)
      .then((result) => {
        if (cancelled) {
          return;
        }
        setSentStats(result.data);
        setSentStatsState('ready');
      })
      .catch(() => {
        if (!cancelled) {
          setSentStatsState('error');
        }
      });
    return () => {
      cancelled = true;
    };
  }, [apiKey, tab]);

  useEffect(() => {
    if (tab !== 'webhooks') {
      return;
    }
    let cancelled = false;
    setWebhooksState('loading');
    void fetchWebhooks(apiKey)
      .then((list) => {
        if (cancelled) {
          return;
        }
        setWebhooks(list);
        setWebhooksState('ready');
      })
      .catch((error: unknown) => {
        if (cancelled) {
          return;
        }
        setWebhooksState(error instanceof ApiError && error.isForbidden ? 'forbidden' : 'error');
      });
    return () => {
      cancelled = true;
    };
  }, [apiKey, tab, webhooksToken]);

  const copy = useCallback(
    (text: string) => {
      if (navigator.clipboard === undefined) {
        notify('error', t('toast.error'));
        return;
      }
      void navigator.clipboard
        .writeText(text)
        .then(() => notify('success', t('toast.copied')))
        .catch(() => notify('error', t('toast.error')));
    },
    [notify, t],
  );

  const formatDate = useCallback(
    (iso: string | undefined | null): string => {
      if (iso === undefined || iso === null || iso.length === 0) {
        return '—';
      }
      const parsed = new Date(iso);
      return Number.isNaN(parsed.getTime())
        ? '—'
        : new Intl.DateTimeFormat(i18n.language, { dateStyle: 'medium' }).format(parsed);
    },
    [i18n.language],
  );

  const toggleScope = useCallback((scope: Scope) => {
    setScopes((current) => {
      const next = new Set(current);
      if (next.has(scope)) {
        next.delete(scope);
      } else {
        next.add(scope);
      }
      return next;
    });
  }, []);

  const toggleEvent = useCallback((event: WebhookEvent) => {
    setWebhookEvents((current) => {
      const next = new Set(current);
      if (next.has(event)) {
        next.delete(event);
      } else {
        next.add(event);
      }
      return next;
    });
  }, []);

  const submitKey = useCallback(
    (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (scopes.size === 0) {
        setKeysError(t('settings.scopeRequired'));
        return;
      }
      setKeysError(null);
      setCreatingKey(true);
      const name = keyName.trim().length > 0 ? keyName.trim() : 'webmail';
      void createApiKey(apiKey, name, [...scopes], sandbox)
        .then((created) => {
          setCreatedKey(created.key);
          setKeyName('');
          setKeysToken((token) => token + 1);
          notify('success', t('toast.keyCreated'));
        })
        .catch((error: unknown) => {
          if (error instanceof ApiError && error.isForbidden) {
            setKeysState('forbidden');
          } else {
            setKeysError(t('toast.error'));
          }
        })
        .finally(() => setCreatingKey(false));
    },
    [apiKey, keyName, notify, sandbox, scopes, t],
  );

  const revoke = useCallback(
    (id: string) => {
      if (pendingRevoke !== id) {
        setPendingRevoke(id);
        return;
      }
      setBusyKey(id);
      void revokeApiKey(apiKey, id)
        .then(() => {
          setKeys((current) => current.map((key) => (key.id === id ? { ...key, revoked: true } : key)));
          notify('success', t('toast.revoked'));
        })
        .catch(() => notify('error', t('toast.error')))
        .finally(() => {
          setBusyKey(null);
          setPendingRevoke(null);
        });
    },
    [apiKey, notify, pendingRevoke, t],
  );

  const submitWebhook = useCallback(
    (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      const url = webhookUrl.trim();
      if (!/^https?:\/\/[^\s]+$/.test(url)) {
        setWebhooksError(t('toast.error'));
        return;
      }
      if (webhookEvents.size === 0) {
        setWebhooksError(t('settings.eventsHint'));
        return;
      }
      setWebhooksError(null);
      setCreatingWebhook(true);
      void createWebhook(apiKey, url, [...webhookEvents])
        .then((created) => {
          setCreatedSecret(created.secret);
          setWebhookUrl('');
          setWebhooksToken((token) => token + 1);
          notify('success', t('toast.webhookCreated'));
        })
        .catch((error: unknown) => {
          if (error instanceof ApiError && error.isForbidden) {
            setWebhooksState('forbidden');
          } else {
            setWebhooksError(t('toast.error'));
          }
        })
        .finally(() => setCreatingWebhook(false));
    },
    [apiKey, notify, t, webhookEvents, webhookUrl],
  );

  const removeWebhook = useCallback(
    (id: string) => {
      if (pendingDelete !== id) {
        setPendingDelete(id);
        return;
      }
      setBusyWebhook(id);
      void deleteWebhook(apiKey, id)
        .then(() => {
          setWebhooks((current) => current.filter((webhook) => webhook.id !== id));
          notify('success', t('toast.webhookDeleted'));
        })
        .catch(() => notify('error', t('toast.error')))
        .finally(() => {
          setBusyWebhook(null);
          setPendingDelete(null);
        });
    },
    [apiKey, notify, pendingDelete, t],
  );

  const keysBody = useMemo(() => {
    if (keysState === 'loading' || keysState === 'idle') {
      return (
        <div className="stack" aria-busy="true" aria-label={t('common.loading')}>
          <span className="skeleton skeleton--line" />
          <span className="skeleton skeleton--line skeleton--short" />
        </div>
      );
    }
    if (keysState === 'forbidden' || keysState === 'error') {
      const forbidden = keysState === 'forbidden';
      return (
        <div className="state-card state-card--compact" role="alert">
          <span className={`state-card__icon${forbidden ? ' state-card__icon--warn' : ''}`}>
            {forbidden ? <ShieldAlert size={20} /> : <AlertTriangle size={20} />}
          </span>
          <h3>{forbidden ? t('settings.forbidden') : t('settings.loadError')}</h3>
          {forbidden ? null : (
            <button type="button" className="btn btn--ghost" onClick={() => setKeysToken((token) => token + 1)}>
              <RefreshCw size={15} aria-hidden="true" />
              {t('common.retry')}
            </button>
          )}
        </div>
      );
    }
    if (keys.length === 0) {
      return <p className="panel__empty">{t('settings.keysEmpty')}</p>;
    }
    return (
      <ul className="record-list">
        {keys.map((key) => (
          <li className="record" key={key.id}>
            <span className="record__icon" aria-hidden="true">
              <KeyRound size={16} />
            </span>
            <div className="record__main">
              <div className="record__title">
                <span>{key.name}</span>
                {key.revoked === true ? <span className="badge badge--bad">{t('settings.revoked')}</span> : null}
                {key.sandbox === true ? <span className="badge badge--muted">{t('settings.sandbox')}</span> : null}
              </div>
              <div className="record__meta">
                {key.scopes.map((scope) => (
                  <span className="badge badge--scope" key={scope}>
                    {t(SCOPE_LABELS[scope])}
                  </span>
                ))}
                <span>
                  {t('settings.created')} {formatDate(key.created_at)}
                </span>
                <span>
                  {t('settings.lastUsed')} {key.last_used_at !== undefined && key.last_used_at !== null ? formatDate(key.last_used_at) : t('settings.never')}
                </span>
              </div>
            </div>
            {key.revoked === true ? null : (
              <button
                type="button"
                className={`btn btn--small ${pendingRevoke === key.id ? 'btn--danger' : 'btn--ghost'}`}
                onClick={() => revoke(key.id)}
                disabled={busyKey === key.id}
              >
                {busyKey === key.id ? <Loader2 size={14} className="spin" aria-hidden="true" /> : null}
                {pendingRevoke === key.id ? `${t('common.revoke')}?` : t('common.revoke')}
              </button>
            )}
          </li>
        ))}
      </ul>
    );
  }, [keys, keysState, busyKey, pendingRevoke, revoke, formatDate, t]);

  const webhooksBody = useMemo(() => {
    if (webhooksState === 'loading' || webhooksState === 'idle') {
      return (
        <div className="stack" aria-busy="true" aria-label={t('common.loading')}>
          <span className="skeleton skeleton--line" />
          <span className="skeleton skeleton--line skeleton--short" />
        </div>
      );
    }
    if (webhooksState === 'forbidden' || webhooksState === 'error') {
      const forbidden = webhooksState === 'forbidden';
      return (
        <div className="state-card state-card--compact" role="alert">
          <span className={`state-card__icon${forbidden ? ' state-card__icon--warn' : ''}`}>
            {forbidden ? <ShieldAlert size={20} /> : <AlertTriangle size={20} />}
          </span>
          <h3>{forbidden ? t('settings.forbidden') : t('settings.loadError')}</h3>
          {forbidden ? null : (
            <button type="button" className="btn btn--ghost" onClick={() => setWebhooksToken((token) => token + 1)}>
              <RefreshCw size={15} aria-hidden="true" />
              {t('common.retry')}
            </button>
          )}
        </div>
      );
    }
    if (webhooks.length === 0) {
      return <p className="panel__empty">{t('settings.webhooksEmpty')}</p>;
    }
    return (
      <ul className="record-list">
        {webhooks.map((webhook) => (
          <li className="record" key={webhook.id}>
            <span className="record__icon" aria-hidden="true">
              <WebhookIcon size={16} />
            </span>
            <div className="record__main">
              <div className="record__title">
                <code className="record__url">{webhook.url}</code>
              </div>
              <div className="record__meta">
                {webhook.events.map((event) => (
                  <span className="badge badge--scope" key={event}>
                    {event}
                  </span>
                ))}
                <span>{formatDate(webhook.created_at)}</span>
              </div>
            </div>
            <button
              type="button"
              className={`btn btn--small ${pendingDelete === webhook.id ? 'btn--danger' : 'btn--ghost'}`}
              onClick={() => removeWebhook(webhook.id)}
              disabled={busyWebhook === webhook.id}
            >
              {busyWebhook === webhook.id ? (
                <Loader2 size={14} className="spin" aria-hidden="true" />
              ) : (
                <Trash2 size={14} aria-hidden="true" />
              )}
              {pendingDelete === webhook.id ? `${t('settings.deleteWebhook')}?` : t('settings.deleteWebhook')}
            </button>
          </li>
        ))}
      </ul>
    );
  }, [webhooks, webhooksState, busyWebhook, pendingDelete, removeWebhook, formatDate, t]);

  return (
    <section className="settings" aria-label={t('settings.title')}>
      <header className="settings__head">
        <div>
          <h1 className="settings__title">{t('settings.title')}</h1>
          <p className="settings__subtitle">{t('settings.subtitle')}</p>
        </div>
        <div className="settings__tabs" role="tablist" aria-label={t('settings.title')} onKeyDown={onTabKeyDown}>
          <button
            type="button"
            role="tab"
            id="settings-tab-overview"
            aria-controls="settings-panel-overview"
            aria-selected={tab === 'overview'}
            tabIndex={tab === 'overview' ? 0 : -1}
            className={`settings__tab${tab === 'overview' ? ' is-active' : ''}`}
            onClick={() => setTab('overview')}
          >
            <SlidersHorizontal size={15} aria-hidden="true" />
            {t('settings.tabOverview', 'Overview')}
          </button>
          <button
            type="button"
            role="tab"
            id="settings-tab-keys"
            aria-controls="settings-panel-keys"
            aria-selected={tab === 'keys'}
            tabIndex={tab === 'keys' ? 0 : -1}
            className={`settings__tab${tab === 'keys' ? ' is-active' : ''}`}
            onClick={() => setTab('keys')}
          >
            <KeyRound size={15} aria-hidden="true" />
            {t('settings.tabKeys')}
          </button>
          <button
            type="button"
            role="tab"
            id="settings-tab-webhooks"
            aria-controls="settings-panel-webhooks"
            aria-selected={tab === 'webhooks'}
            tabIndex={tab === 'webhooks' ? 0 : -1}
            className={`settings__tab${tab === 'webhooks' ? ' is-active' : ''}`}
            onClick={() => setTab('webhooks')}
          >
            <WebhookIcon size={15} aria-hidden="true" />
            {t('settings.tabWebhooks')}
          </button>
          <button
            type="button"
            role="tab"
            id="settings-tab-preferences"
            aria-controls="settings-panel-preferences"
            aria-selected={tab === 'preferences'}
            tabIndex={tab === 'preferences' ? 0 : -1}
            className={`settings__tab${tab === 'preferences' ? ' is-active' : ''}`}
            onClick={() => setTab('preferences')}
          >
            <SlidersHorizontal size={15} aria-hidden="true" />
            {t('settings.tabPreferences')}
          </button>
          <button
            type="button"
            role="tab"
            id="settings-tab-templates"
            aria-controls="settings-panel-templates"
            aria-selected={tab === 'templates'}
            tabIndex={tab === 'templates' ? 0 : -1}
            className={`settings__tab${tab === 'templates' ? ' is-active' : ''}`}
            onClick={() => setTab('templates')}
          >
            {t('settings.tabTemplates')}
          </button>
          <button
            type="button"
            role="tab"
            id="settings-tab-domains"
            aria-controls="settings-panel-domains"
            aria-selected={tab === 'domains'}
            tabIndex={tab === 'domains' ? 0 : -1}
            className={`settings__tab${tab === 'domains' ? ' is-active' : ''}`}
            onClick={() => setTab('domains')}
          >
            {t('settings.tabDomains')}
          </button>
          <button
            type="button"
            role="tab"
            id="settings-tab-suppressions"
            aria-controls="settings-panel-suppressions"
            aria-selected={tab === 'suppressions'}
            tabIndex={tab === 'suppressions' ? 0 : -1}
            className={`settings__tab${tab === 'suppressions' ? ' is-active' : ''}`}
            onClick={() => setTab('suppressions')}
          >
            {t('settings.tabSuppressions')}
          </button>
          <button
            type="button"
            role="tab"
            id="settings-tab-security"
            aria-controls="settings-panel-security"
            aria-selected={tab === 'security'}
            tabIndex={tab === 'security' ? 0 : -1}
            className={`settings__tab${tab === 'security' ? ' is-active' : ''}`}
            onClick={() => setTab('security')}
          >
            🛡️ {t('settings.tabSecurity')}
          </button>
        </div>
      </header>

      {tab === 'overview' ? (
        <div
          className="settings__panels"
          role="tabpanel"
          id="settings-panel-overview"
          aria-labelledby="settings-tab-overview"
        >
          <OverviewPanel sent={sentStats} state={sentStatsState} />
        </div>
      ) : null}

      {tab === 'templates' ? (
        <div
          className="settings__panels settings__panels--single"
          role="tabpanel"
          id="settings-panel-templates"
          aria-labelledby="settings-tab-templates"
        >
          <TemplatesPanel apiKey={apiKey} notify={notify} />
        </div>
      ) : null}

      {tab === 'domains' ? (
        <div
          className="settings__panels settings__panels--single"
          role="tabpanel"
          id="settings-panel-domains"
          aria-labelledby="settings-tab-domains"
        >
          <DomainsPanel apiKey={apiKey} notify={notify} />
        </div>
      ) : null}

      {tab === 'suppressions' ? (
        <div
          className="settings__panels settings__panels--single"
          role="tabpanel"
          id="settings-panel-suppressions"
          aria-labelledby="settings-tab-suppressions"
        >
          <SuppressionsPanel apiKey={apiKey} notify={notify} />
        </div>
      ) : null}

      {tab === 'security' ? (
        <div
          className="settings__panels settings__panels--single"
          role="tabpanel"
          id="settings-panel-security"
          aria-labelledby="settings-tab-security"
        >
          <SecurityPanel notify={notify} />
        </div>
      ) : null}

      {tab === 'keys' ? (
        <div
          className="settings__panels"
          role="tabpanel"
          id="settings-panel-keys"
          aria-labelledby="settings-tab-keys"
        >
          <section className="panel">
            <div className="panel__head">
              <h2>{t('settings.keysTitle')}</h2>
              <p>{t('settings.keysBody')}</p>
            </div>
            {keysBody}
          </section>

          <section className="panel">
            <div className="panel__head">
              <h2>
                <Plus size={15} aria-hidden="true" />
                {t('settings.createKey')}
              </h2>
            </div>
            {createdKey !== null ? (
              <div className="secret-reveal" role="status">
                <div className="secret-reveal__head">
                  <Lock size={14} aria-hidden="true" />
                  <span>{t('settings.keyCreated')}</span>
                </div>
                <div className="secret-reveal__value">
                  <code>{createdKey}</code>
                  <button type="button" className="btn btn--quiet btn--small" onClick={() => copy(createdKey)}>
                    <Copy size={14} aria-hidden="true" />
                    {t('common.copy')}
                  </button>
                </div>
              </div>
            ) : null}
            <form className="settings__form" onSubmit={submitKey}>
              <label className="field field--plain">
                <span className="field__label">{t('settings.keyName')}</span>
                <input
                  className="input"
                  type="text"
                  value={keyName}
                  placeholder={t('settings.keyNamePlaceholder')}
                  onChange={(event) => setKeyName(event.target.value)}
                />
              </label>

              <fieldset className="fieldset">
                <legend className="field__label">{t('settings.scopes')}</legend>
                <div className="chip-row">
                  {SCOPES.map((scope) => {
                    const active = scopes.has(scope);
                    return (
                      <button
                        type="button"
                        key={scope}
                        className={`chip${active ? ' is-active' : ''}`}
                        aria-pressed={active}
                        onClick={() => toggleScope(scope)}
                      >
                        {active ? <Check size={13} aria-hidden="true" /> : null}
                        {t(SCOPE_LABELS[scope])}
                      </button>
                    );
                  })}
                </div>
              </fieldset>

              <label className="check">
                <input
                  type="checkbox"
                  checked={sandbox}
                  onChange={(event) => setSandbox(event.target.checked)}
                />
                <span>{t('settings.sandbox')}</span>
              </label>

              {keysError !== null ? (
                <p className="field__error" role="alert">
                  {keysError}
                </p>
              ) : null}

              <button type="submit" className="btn btn--primary" disabled={creatingKey}>
                {creatingKey ? (
                  <Loader2 size={15} className="spin" aria-hidden="true" />
                ) : (
                  <Plus size={15} aria-hidden="true" />
                )}
                {creatingKey ? t('settings.creating') : t('settings.createKey')}
              </button>
            </form>
          </section>
        </div>
      ) : null}

      {tab === 'webhooks' ? (
        <div
          className="settings__panels"
          role="tabpanel"
          id="settings-panel-webhooks"
          aria-labelledby="settings-tab-webhooks"
        >
          <section className="panel">
            <div className="panel__head">
              <h2>{t('settings.webhooksTitle')}</h2>
              <p>{t('settings.webhooksBody')}</p>
            </div>
            {webhooksBody}
          </section>

          <section className="panel">
            <div className="panel__head">
              <h2>
                <Plus size={15} aria-hidden="true" />
                {t('settings.createWebhook')}
              </h2>
            </div>
            {createdSecret !== null ? (
              <div className="secret-reveal" role="status">
                <div className="secret-reveal__head">
                  <Lock size={14} aria-hidden="true" />
                  <span>{t('settings.webhookCreated')}</span>
                </div>
                <div className="secret-reveal__value">
                  <code>{createdSecret}</code>
                  <button type="button" className="btn btn--quiet btn--small" onClick={() => copy(createdSecret)}>
                    <Copy size={14} aria-hidden="true" />
                    {t('common.copy')}
                  </button>
                </div>
              </div>
            ) : null}
            <form className="settings__form" onSubmit={submitWebhook}>
              <label className="field field--plain">
                <span className="field__label">{t('settings.webhookUrl')}</span>
                <input
                  className="input"
                  type="url"
                  inputMode="url"
                  value={webhookUrl}
                  placeholder={t('settings.webhookUrlPlaceholder')}
                  onChange={(event) => setWebhookUrl(event.target.value)}
                />
              </label>

              <fieldset className="fieldset">
                <legend className="field__label">{t('settings.webhookEvents')}</legend>
                <div className="chip-row chip-row--wrap">
                  {WEBHOOK_EVENTS.map((event) => {
                    const active = webhookEvents.has(event);
                    return (
                      <button
                        type="button"
                        key={event}
                        className={`chip${active ? ' is-active' : ''}`}
                        aria-pressed={active}
                        onClick={() => toggleEvent(event)}
                      >
                        {active ? <Check size={13} aria-hidden="true" /> : null}
                        {event}
                      </button>
                    );
                  })}
                </div>
              </fieldset>

              {webhooksError !== null ? (
                <p className="field__error" role="alert">
                  {webhooksError}
                </p>
              ) : null}

              <button type="submit" className="btn btn--primary" disabled={creatingWebhook}>
                {creatingWebhook ? (
                  <Loader2 size={15} className="spin" aria-hidden="true" />
                ) : (
                  <Plus size={15} aria-hidden="true" />
                )}
                {t('settings.createWebhook')}
              </button>
            </form>
          </section>
        </div>
      ) : null}

      {tab === 'preferences' ? (
        <div
          className="settings__panels settings__panels--single"
          role="tabpanel"
          id="settings-panel-preferences"
          aria-labelledby="settings-tab-preferences"
        >
          <section className="panel">
            <div className="panel__head">
              <h2>{t('settings.preferencesTitle')}</h2>
              <p>{t('settings.preferencesBody')}</p>
            </div>

            <div className="pref-list">
              <div className="pref-row">
                <div className="pref-row__text">
                  <span className="pref-row__label">{t('common.language')}</span>
                  <p>{t('settings.languageHelp')}</p>
                </div>
                <LanguageSelect lang={lang} onChange={onLangChange} />
              </div>

              <div className="pref-row">
                <div className="pref-row__text">
                  <span className="pref-row__label">{t('common.theme')}</span>
                  <p>{t('settings.themeHelp')}</p>
                </div>
                <div className="segmented segmented--wide">
                  <button
                    type="button"
                    className={`segmented__item${theme === 'light' ? ' is-active' : ''}`}
                    aria-pressed={theme === 'light'}
                    onClick={() => onThemeChange('light')}
                  >
                    <Sun size={14} aria-hidden="true" />
                    {t('common.light')}
                  </button>
                  <button
                    type="button"
                    className={`segmented__item${theme === 'dark' ? ' is-active' : ''}`}
                    aria-pressed={theme === 'dark'}
                    onClick={() => onThemeChange('dark')}
                  >
                    <Moon size={14} aria-hidden="true" />
                    {t('common.dark')}
                  </button>
                </div>
              </div>

              <div className="pref-row">
                <div className="pref-row__text">
                  <span className="pref-row__label">{t('common.motion')}</span>
                  <p>{t('settings.motionHelp')}</p>
                </div>
                <MotionSwitch motion={motion} onToggle={() => onMotionChange(!motion)} />
              </div>

              <div className="pref-row pref-row--danger">
                <div className="pref-row__text">
                  <span className="pref-row__label">{t('settings.dangerZone')}</span>
                  <p>{t('settings.dangerBody')}</p>
                </div>
                <button type="button" className="btn btn--danger" onClick={onSignOut}>
                  <LogOut size={15} aria-hidden="true" />
                  {t('common.signOut')}
                </button>
              </div>
            </div>
          </section>
        </div>
      ) : null}
    </section>
  );
}

// ---------------------------------------------------------------------------
// Overview panel (artboard 04 Cockpit Admin): stat cards + 14-day volume chart
// ---------------------------------------------------------------------------

interface OverviewStats {
  sent24h: number;
  deliveredPct: number;
  inQueue: number;
  bouncedPct: number;
  dailyCounts: number[];
}

function computeOverview(sent: SentMessage[]): OverviewStats {
  const now = Date.now();
  const dayMs = 86_400_000;

  let sent24h = 0;
  let delivered = 0;
  let bounced = 0;
  let queued = 0;
  const buckets = new Map<string, number>();

  for (const msg of sent) {
    const created = Date.parse(msg.created_at);
    const age = Number.isFinite(created) ? now - created : Infinity;
    if (age <= dayMs) {
      sent24h += 1;
    }
    if (msg.status === 'sent') {
      delivered += 1;
    } else if (msg.status === 'bounced' || msg.status === 'failed') {
      bounced += 1;
    } else if (msg.status === 'queued' || msg.status === 'scheduled' || msg.status === 'deferred') {
      queued += 1;
    }
    if (Number.isFinite(created)) {
      const dayKey = new Date(created).toISOString().slice(0, 10);
      buckets.set(dayKey, (buckets.get(dayKey) ?? 0) + 1);
    }
  }

  // 14-day series, oldest first.
  const dailyCounts: number[] = [];
  for (let i = 13; i >= 0; i -= 1) {
    const key = new Date(now - i * dayMs).toISOString().slice(0, 10);
    dailyCounts.push(buckets.get(key) ?? 0);
  }

  const total = sent.length || 1;
  return {
    sent24h,
    deliveredPct: Math.round((delivered / total) * 1000) / 10,
    inQueue: queued,
    bouncedPct: Math.round((bounced / total) * 1000) / 10,
    dailyCounts,
  };
}

function OverviewPanel({
  sent,
  state,
}: {
  sent: SentMessage[];
  state: LoadState;
}): JSX.Element {
  const { t } = useTranslation();

  if (state === 'loading') {
    return (
      <div className="overview">
        <p className="overview__loading">
          <Loader2 size={16} className="spin" aria-hidden="true" /> {t('common.loading')}
        </p>
      </div>
    );
  }
  if (state === 'error') {
    return (
      <div className="overview">
        <p className="overview__loading" role="alert">
          <AlertTriangle size={16} aria-hidden="true" /> {t('common.error')}
        </p>
      </div>
    );
  }

  const stats = computeOverview(sent);
  const max = Math.max(...stats.dailyCounts, 1);

  const cards: Array<{ label: string; value: string; detail: string; tone?: 'up' | 'warn' }> = [
    {
      label: t('admin.sent24h', 'Sent · 24h'),
      value: String(stats.sent24h),
      detail: `${t('admin.total', { count: sent.length, defaultValue: `${sent.length} total` })}`,
      tone: 'up',
    },
    {
      label: t('admin.delivered', 'Delivered'),
      value: `${stats.deliveredPct}%`,
      detail: t('admin.deliveredDetail', 'of all tracked sends'),
    },
    {
      label: t('admin.inQueue', 'In queue'),
      value: String(stats.inQueue),
      detail:
        stats.inQueue > 0
          ? t('admin.queueDetail', 'retrying with backoff')
          : t('admin.queueEmpty', 'queue drained'),
      tone: stats.inQueue > 0 ? 'warn' : undefined,
    },
    {
      label: t('admin.bounced', 'Bounced'),
      value: `${stats.bouncedPct}%`,
      detail: t('admin.bounceDetail', 'hard bounces auto-suppressed'),
    },
  ];

  return (
    <div className="overview">
      <div className="overview__stats">
        {cards.map((card) => (
          <div key={card.label} className="overview__stat">
            <span className="overview__stat-label">{card.label}</span>
            <span className="overview__stat-value">{card.value}</span>
            <span className={`overview__stat-detail${card.tone ? ` is-${card.tone}` : ''}`}>
              {card.detail}
            </span>
          </div>
        ))}
      </div>
      <div className="overview__chart card">
        <header className="overview__chart-head">
          <h2>{t('admin.volume', 'Send volume · last 14 days')}</h2>
        </header>
        <div
          className="overview__bars"
          role="img"
          aria-label={t('admin.volumeAria', 'Bar chart of sends per day over the last 14 days')}
        >
          {stats.dailyCounts.map((count, index) => (
            <i
              key={index}
              style={{ height: `${Math.max((count / max) * 100, 3)}%` }}
              title={`${count}`}
            />
          ))}
        </div>
        <p className="overview__chart-foot">{t('admin.volumeFoot', 'last 14 days, oldest → newest')}</p>
      </div>
    </div>
  );
}

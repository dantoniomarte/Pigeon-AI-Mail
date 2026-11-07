import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  AlertTriangle,
  AtSign,
  BellOff,
  BellRing,
  FileText,
  Globe,
  Loader2,
  Plus,
  Send,
  ShieldOff,
  Trash2,
} from 'lucide-react';

import {
  ApiError,
  addSuppressions,
  createTemplate,
  deleteTemplate,
  fetchAliases,
  fetchCatchalls,
  fetchDomainDns,
  fetchDomains,
  fetchSuppressions,
  fetchTemplates,
  pauseMyCatchall,
  removeSuppression,
  resumeMyCatchall,
  testSendTemplate,
  type AliasView,
  type CatchallAssignment,
  type CatchallRuleView,
  type DnsRecord,
  type DomainView,
  type SuppressionEntry,
  type Template,
} from '../api';
import type { LoadState } from '../App';
import type { ToastKind } from './Toast';

interface PanelsProps {
  apiKey: string | null;
  notify: (kind: ToastKind, message: string) => void;
}

/** Suppression reasons are API enums; the badge shows localized copy instead. */
const REASON_KEYS: Record<SuppressionEntry['reason'], string> = {
  manual: 'settings.reasonManual',
  bounce: 'settings.reasonBounce',
  complaint: 'settings.reasonComplaint',
};

// ---------------------------------------------------------------------------
// Templates
// ---------------------------------------------------------------------------

export function TemplatesPanel({ apiKey, notify }: PanelsProps): JSX.Element {
  const { t } = useTranslation();
  const [templates, setTemplates] = useState<Template[]>([]);
  const [state, setState] = useState<LoadState>('idle');
  const [token, setToken] = useState(0);

  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [subject, setSubject] = useState('');
  const [text, setText] = useState('');
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // One test recipient per template row: typing in one row never overwrites the
  // address typed in another.
  const [testTo, setTestTo] = useState<Record<string, string>>({});
  const [testingId, setTestingId] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setState('loading');
    void fetchTemplates(apiKey)
      .then((list) => { if (!cancelled) { setTemplates(list); setState('ready'); } })
      .catch(() => { if (!cancelled) setState('error'); });
    return () => { cancelled = true; };
  }, [apiKey, token]);

  const submit = useCallback((event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!name.trim() || creating) return;
    setCreating(true);
    setError(null);
    void createTemplate(apiKey, {
      name: name.trim(),
      description: description.trim(),
      subject: subject.trim(),
      text,
    })
      .then(() => {
        setCreating(false);
        setName(''); setDescription(''); setSubject(''); setText('');
        setToken((value) => value + 1);
        notify('success', t('toast.templateCreated'));
      })
      .catch((err: unknown) => {
        setCreating(false);
        setError(err instanceof ApiError && err.status === 409 ? t('settings.tplDuplicate') : t('common.error'));
      });
  }, [apiKey, creating, description, name, notify, subject, t, text]);

  const runTest = useCallback((id: string) => {
    const recipients = (testTo[id] ?? '').split(/[,;\s]+/).filter(Boolean);
    if (recipients.length === 0) { notify('error', t('settings.testNeedsTo')); return; }
    setTestingId(id);
    void testSendTemplate(apiKey, id, recipients, {})
      .then(() => { setTestingId(null); notify('success', t('toast.testSent')); })
      .catch(() => { setTestingId(null); notify('error', t('toast.testFailed')); });
  }, [apiKey, notify, t, testTo]);

  return (
    <section className="panel">
      <div className="panel__head">
        <h2><FileText size={15} aria-hidden="true" /> {t('settings.templatesTitle')}</h2>
        <p>{t('settings.templatesBody')}</p>
      </div>
      {state === 'loading' ? <Loader2 className="spin" aria-hidden="true" /> : null}
      {state === 'error' ? <p role="alert" className="settings__error"><AlertTriangle size={14} /> {t('common.error')}</p> : null}
      {state === 'ready' ? (
        templates.length === 0 ? (
          <p className="panel__empty">{t('settings.noTemplates')}</p>
        ) : (
          <ul className="tpl-list">
            {templates.map((tpl) => (
              <li key={tpl.id} className="tpl-list__item">
                <div className="tpl-list__info">
                  <b>{tpl.name}</b>
                  {tpl.description ? <span className="tpl-list__description">{tpl.description}</span> : null}
                  {tpl.subject ? <span className="tpl-list__subject">{tpl.subject}</span> : null}
                </div>
                <div className="tpl-list__actions">
                  <input
                    className="input input--small"
                    type="email"
                    placeholder={t('settings.testToPlaceholder')}
                    aria-label={t('settings.testToPlaceholder')}
                    value={testTo[tpl.id] ?? ''}
                    onChange={(event) =>
                      setTestTo((current) => ({ ...current, [tpl.id]: event.target.value }))
                    }
                  />
                  <button
                    type="button"
                    className="btn btn--ghost btn--small"
                    disabled={testingId !== null}
                    onClick={() => runTest(tpl.id)}
                  >
                    <Send size={13} aria-hidden="true" /> {t('settings.testSend')}
                  </button>
                  <button
                    type="button"
                    className="btn btn--ghost btn--small"
                    onClick={() => {
                      void deleteTemplate(apiKey, tpl.id)
                        .then(() => setToken((value) => value + 1))
                        .catch(() => notify('error', t('common.error')));
                    }}
                  >
                    <Trash2 size={13} aria-hidden="true" /> {t('common.delete')}
                  </button>
                </div>
              </li>
            ))}
          </ul>
        )
      ) : null}
      <form className="settings__form" onSubmit={submit}>
        <label className="field field--plain">
          <span className="field__label">{t('settings.tplName')}</span>
          <input className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder={t('settings.tplNamePlaceholder')} required />
        </label>
        <label className="field field--plain">
          <span className="field__label">{t('settings.tplDescription')}</span>
          <textarea
            className="input"
            rows={2}
            maxLength={500}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder={t('settings.tplDescriptionPlaceholder')}
          />
        </label>
        <label className="field field--plain">
          <span className="field__label">{t('settings.tplSubject')}</span>
          <input className="input" value={subject} onChange={(e) => setSubject(e.target.value)} placeholder={t('settings.tplSubjectPlaceholder')} />
        </label>
        <label className="field field--plain">
          <span className="field__label">{t('settings.tplBody')}</span>
          <textarea className="input" rows={3} value={text} onChange={(e) => setText(e.target.value)} placeholder={t('settings.tplBodyPlaceholder')} />
        </label>
        {error !== null ? <p className="settings__error" role="alert">{error}</p> : null}
        <button type="submit" className="btn btn--primary" disabled={creating}>
          {creating ? <Loader2 size={15} className="spin" aria-hidden="true" /> : <Plus size={15} aria-hidden="true" />}
          {t('settings.createTemplate')}
        </button>
      </form>
    </section>
  );
}

// ---------------------------------------------------------------------------
// Domains
// ---------------------------------------------------------------------------

export function DomainsPanel({ apiKey }: PanelsProps): JSX.Element {
  const { t } = useTranslation();
  const [domains, setDomains] = useState<DomainView[]>([]);
  const [dns, setDns] = useState<Record<string, DnsRecord[]>>({});
  const [state, setState] = useState<LoadState>('idle');
  const [openId, setOpenId] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setState('loading');
    void fetchDomains(apiKey)
      .then((list) => { if (!cancelled) { setDomains(list); setState('ready'); } })
      .catch(() => { if (!cancelled) setState('error'); });
    return () => { cancelled = true; };
  }, [apiKey]);

  const toggleDns = useCallback((domain: DomainView) => {
    if (openId === domain.id) { setOpenId(null); return; }
    setOpenId(domain.id);
    if (dns[domain.id] === undefined) {
      void fetchDomainDns(apiKey, domain.id)
        .then((records) => setDns((prev) => ({ ...prev, [domain.id]: records })))
        .catch(() => setDns((prev) => ({ ...prev, [domain.id]: [] })));
    }
  }, [apiKey, dns, openId]);

  return (
    <section className="panel">
      <div className="panel__head">
        <h2><Globe size={15} aria-hidden="true" /> {t('settings.domainsTitle')}</h2>
        <p>{t('settings.domainsBody')}</p>
      </div>
      {state === 'loading' ? <Loader2 className="spin" aria-hidden="true" /> : null}
      {state === 'error' ? <p role="alert" className="settings__error"><AlertTriangle size={14} /> {t('common.error')}</p> : null}
      {state === 'ready' ? (
        domains.length === 0 ? (
          <p className="panel__empty">{t('settings.noDomains')}</p>
        ) : (
          <ul className="domain-list">
            {domains.map((domain) => (
              <li key={domain.id} className="domain-list__item">
                <button type="button" className="domain-list__row" onClick={() => toggleDns(domain)} aria-expanded={openId === domain.id}>
                  <b>{domain.name}</b>
                  <span className={`badge badge--${domain.verified ? 'ok' : 'warn'}`}>
                    {domain.verified ? t('settings.domainVerified') : t('settings.domainPending')}
                  </span>
                </button>
                {openId === domain.id ? (
                  <div className="domain-list__dns">
                    {dns[domain.id] === undefined ? (
                      <Loader2 size={14} className="spin" aria-hidden="true" />
                    ) : (
                      <table className="dns-table">
                        <thead><tr><th>{t('settings.dnsType')}</th><th>{t('settings.dnsHost')}</th><th>{t('settings.dnsValue')}</th></tr></thead>
                        <tbody>
                          {(dns[domain.id] ?? []).map((record) => (
                            <tr key={`${record.type}-${record.host}`}>
                              <td>{record.type}</td>
                              <td className="mono">{record.host}</td>
                              <td className="mono dns-value">
                                {record.value}
                                {record.priority != null
                                  ? ` (${t('settings.dnsPriority', { priority: record.priority })})`
                                  : ''}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    )}
                    <p className="hint">{t('settings.dnsHint')}</p>
                  </div>
                ) : null}
              </li>
            ))}
          </ul>
        )
      ) : null}
    </section>
  );
}

// ---------------------------------------------------------------------------
// Suppressions
// ---------------------------------------------------------------------------

export function SuppressionsPanel({ apiKey, notify }: PanelsProps): JSX.Element {
  const { t } = useTranslation();
  const [entries, setEntries] = useState<SuppressionEntry[]>([]);
  const [state, setState] = useState<LoadState>('idle');
  const [token, setToken] = useState(0);
  const [newAddress, setNewAddress] = useState('');
  const [adding, setAdding] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setState('loading');
    void fetchSuppressions(apiKey)
      .then((list) => { if (!cancelled) { setEntries(list); setState('ready'); } })
      .catch(() => { if (!cancelled) setState('error'); });
    return () => { cancelled = true; };
  }, [apiKey, token]);

  const add = useCallback((event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const addresses = newAddress.split(/[,;\s]+/).filter(Boolean);
    if (addresses.length === 0 || adding) return;
    setAdding(true);
    void addSuppressions(apiKey, addresses, 'manual')
      .then(() => { setAdding(false); setNewAddress(''); setToken((value) => value + 1); notify('success', t('toast.suppressionAdded')); })
      .catch(() => { setAdding(false); notify('error', t('common.error')); });
  }, [adding, apiKey, newAddress, notify, t]);

  const remove = useCallback((address: string) => {
    void removeSuppression(apiKey, address)
      .then(() => setToken((value) => value + 1))
      .catch(() => notify('error', t('common.error')));
  }, [apiKey, notify, t]);

  return (
    <section className="panel">
      <div className="panel__head">
        <h2><ShieldOff size={15} aria-hidden="true" /> {t('settings.suppressionsTitle')}</h2>
        <p>{t('settings.suppressionsBody')}</p>
      </div>
      {state === 'loading' ? <Loader2 className="spin" aria-hidden="true" /> : null}
      {state === 'error' ? <p role="alert" className="settings__error"><AlertTriangle size={14} /> {t('common.error')}</p> : null}
      {state === 'ready' ? (
        entries.length === 0 ? (
          <p className="panel__empty">{t('settings.noSuppressions')}</p>
        ) : (
          <ul className="suppression-list">
            {entries.map((entry) => (
              <li key={entry.address} className="suppression-list__item">
                <span className="mono">{entry.address}</span>
                <span className={`badge badge--${entry.reason === 'bounce' ? 'bad' : 'warn'}`}>
                  {t(REASON_KEYS[entry.reason])}
                </span>
                <button type="button" className="btn btn--ghost btn--small" onClick={() => remove(entry.address)}>
                  <Trash2 size={13} aria-hidden="true" /> {t('common.delete')}
                </button>
              </li>
            ))}
          </ul>
        )
      ) : null}
      <form className="settings__form" onSubmit={add}>
        <label className="field field--plain">
          <span className="field__label">{t('settings.suppressAdd')}</span>
          <input className="input" type="email" value={newAddress} onChange={(e) => setNewAddress(e.target.value)} placeholder={t('settings.suppressPlaceholder')} />
        </label>
        <button type="submit" className="btn btn--primary" disabled={adding}>
          {adding ? <Loader2 size={15} className="spin" aria-hidden="true" /> : <Plus size={15} aria-hidden="true" />}
          {t('settings.suppressAddBtn')}
        </button>
      </form>
    </section>
  );
}

// ---------------------------------------------------------------------------
// Send as (sender aliases + the caller's own catch-all copies)
// ---------------------------------------------------------------------------

/**
 * What the account may send as, and which catch-alls it receives.
 *
 * Both are read from the caller's own rows (`?mine=1`): the settings screen is a
 * self view, and administering other people's aliases belongs to the admin panel.
 * The catch-all switch is the member's own pause — the one thing a member may
 * change about a company-wide setting.
 */
export function SendAsPanel({ apiKey, notify }: PanelsProps): JSX.Element {
  const { t } = useTranslation();
  const [aliases, setAliases] = useState<AliasView[]>([]);
  const [rules, setRules] = useState<CatchallRuleView[]>([]);
  const [state, setState] = useState<LoadState>('idle');
  const [token, setToken] = useState(0);
  const [busy, setBusy] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setState('loading');
    void Promise.all([fetchAliases(apiKey, true), fetchCatchalls(apiKey, true)])
      .then(([aliasList, ruleList]) => {
        if (cancelled) {
          return;
        }
        setAliases(aliasList);
        setRules(ruleList);
        setState('ready');
      })
      .catch((error: unknown) => {
        if (cancelled) {
          return;
        }
        setState(error instanceof ApiError && error.isForbidden ? 'forbidden' : 'error');
      });
    return () => {
      cancelled = true;
    };
  }, [apiKey, token]);

  const ownAssignment = (rule: CatchallRuleView): CatchallAssignment | null =>
    rule.assignments !== undefined && rule.assignments.length > 0 ? rule.assignments[0] : null;

  const toggleCatchall = useCallback(
    (domain: string, paused: boolean) => {
      setBusy(domain);
      const call = paused ? resumeMyCatchall(apiKey, domain) : pauseMyCatchall(apiKey, domain);
      void call
        .then(() => {
          notify('success', paused ? t('settings.catchallResumed') : t('settings.catchallPaused'));
          setToken((current) => current + 1);
        })
        .catch(() => notify('error', t('common.error')))
        .finally(() => setBusy(null));
    },
    [apiKey, notify, t],
  );

  const body = ((): JSX.Element => {
    if (state === 'loading' || state === 'idle') {
      return (
        <div className="stack" aria-busy="true" aria-label={t('common.loading')}>
          <span className="skeleton skeleton--line" />
          <span className="skeleton skeleton--line skeleton--short" />
        </div>
      );
    }
    if (state === 'error' || state === 'forbidden') {
      return (
        <div className="state-card state-card--compact" role="alert">
          <span className="state-card__icon">
            <AlertTriangle size={20} />
          </span>
          <h3>{t('settings.sendAsUnavailable')}</h3>
          <button type="button" className="btn btn--ghost" onClick={() => setToken((n) => n + 1)}>
            {t('common.retry')}
          </button>
        </div>
      );
    }
    return (
      <div className="stack">
        <div>
          <h3 className="settings__subtitle">{t('settings.sendAsAliases')}</h3>
          {aliases.length === 0 ? (
            <p className="admin__hint">{t('settings.sendAsNone')}</p>
          ) : (
            <ul className="tag-list">
              {aliases.map((alias) => (
                <li key={alias.id} className="badge badge--enc">
                  <AtSign size={11} aria-hidden="true" />
                  {alias.address}
                </li>
              ))}
            </ul>
          )}
        </div>

        <div>
          <h3 className="settings__subtitle">{t('settings.catchallMine')}</h3>
          {rules.length === 0 ? (
            <p className="admin__hint">{t('settings.catchallMineNone')}</p>
          ) : (
            <ul className="stack">
              {rules.map((rule) => {
                const assignment = ownAssignment(rule);
                const paused = assignment?.paused ?? false;
                return (
                  <li key={rule.domain} className="row-between">
                    <span className="mono">{rule.domain}</span>
                    <span className="badge badge--muted">
                      {paused ? t('settings.catchallPausedBadge') : t('settings.catchallLiveBadge')}
                    </span>
                    <button
                      type="button"
                      className="btn btn--small btn--ghost"
                      onClick={() => toggleCatchall(rule.domain, paused)}
                      disabled={busy === rule.domain}
                    >
                      {busy === rule.domain ? (
                        <Loader2 size={14} className="spin" aria-hidden="true" />
                      ) : paused ? (
                        <BellRing size={14} aria-hidden="true" />
                      ) : (
                        <BellOff size={14} aria-hidden="true" />
                      )}
                      {paused ? t('settings.catchallResume') : t('settings.catchallPause')}
                    </button>
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      </div>
    );
  })();

  return (
    <section className="panel">
      <div className="panel__head">
        <h2>
          <Send size={15} aria-hidden="true" />
          {t('settings.sendAsTitle')}
        </h2>
        <p>{t('settings.sendAsBody')}</p>
      </div>
      {body}
    </section>
  );
}

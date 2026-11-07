import { useCallback, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { AlertTriangle, Check, Copy, Loader2, ShieldCheck, ShieldOff } from 'lucide-react';

import { activate2fa, disable2fa, enroll2fa, verify2fa } from '../api';
import type { ToastKind } from './Toast';

export interface SecurityPanelProps {
  notify: (kind: ToastKind, message: string) => void;
}

type Phase = 'idle' | 'enrolling' | 'recovering';

const TWOFA_STORAGE = 'pigeon_2fa';

/**
 * Remember locally that this account has a second factor.
 *
 * v1 has no `GET /v1/account/2fa/status`, so after a reload the panel cannot ask
 * the server whether 2FA is on. Instead the flag is written when `activate2fa`
 * succeeds and cleared when `disable2fa` succeeds, and the idle UI is derived
 * from it — otherwise the panel would offer enrollment to an account that
 * already has it.
 *
 * Known limitation: the flag is per browser, so enrolling on one device leaves
 * another device showing the enrollment call to action. A status endpoint is the
 * only reload-honest fix and is scheduled as a follow-up on the server surface.
 */
function readTwoFaFlag(): boolean {
  try {
    return localStorage.getItem(TWOFA_STORAGE) === '1';
  } catch {
    return false;
  }
}

function writeTwoFaFlag(active: boolean): void {
  try {
    if (active) {
      localStorage.setItem(TWOFA_STORAGE, '1');
    } else {
      localStorage.removeItem(TWOFA_STORAGE);
    }
  } catch {
    // Storage can be unavailable (private mode); the panel still works per session.
  }
}

export function SecurityPanel({ notify }: SecurityPanelProps): JSX.Element {
  const { t } = useTranslation();
  const [phase, setPhase] = useState<Phase>('idle');
  const [busy, setBusy] = useState(false);
  const [secret, setSecret] = useState<string | null>(null);
  const [otpauthUri, setOtpauthUri] = useState<string | null>(null);
  const [code, setCode] = useState('');
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [has2fa, setHas2fa] = useState<boolean>(() => readTwoFaFlag());

  const startEnroll = useCallback(() => {
    setBusy(true);
    setError(null);
    enroll2fa()
      .then((data) => {
        setSecret(data.secret_base32);
        setOtpauthUri(data.otpauth_uri);
        setPhase('enrolling');
        setBusy(false);
      })
      .catch(() => {
        setBusy(false);
        setError(t('security.enrollFailed'));
      });
  }, [t]);

  const confirmActivate = useCallback(() => {
    if (!code.trim() || busy) return;
    setBusy(true);
    setError(null);
    activate2fa(code.trim())
      .then((codes) => {
        setRecoveryCodes(codes);
        setPhase('recovering');
        setHas2fa(true);
        writeTwoFaFlag(true);
        setBusy(false);
        setCode('');
        notify('success', t('security.activated'));
      })
      .catch(() => {
        setBusy(false);
        setError(t('security.badCode'));
      });
  }, [busy, code, notify, t]);

  const stepUp = useCallback(() => {
    if (!code.trim() || busy) return;
    setBusy(true);
    setError(null);
    verify2fa(code.trim())
      .then(() => {
        setBusy(false);
        setCode('');
        notify('success', t('security.verified'));
      })
      .catch(() => {
        setBusy(false);
        setError(t('security.badCode'));
      });
  }, [busy, code, notify, t]);

  const turnOff = useCallback(() => {
    if (!code.trim() || busy) return;
    setBusy(true);
    setError(null);
    disable2fa(code.trim())
      .then(() => {
        setBusy(false);
        setPhase('idle');
        setSecret(null);
        setRecoveryCodes(null);
        setHas2fa(false);
        writeTwoFaFlag(false);
        setCode('');
        notify('success', t('security.disabled'));
      })
      .catch(() => {
        setBusy(false);
        setError(t('security.badCode'));
      });
  }, [busy, code, notify, t]);

  const copyUri = useCallback(() => {
    if (otpauthUri) {
      void navigator.clipboard.writeText(otpauthUri);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    }
  }, [otpauthUri]);

  // Recovery codes only exist right after activation; after a reload the stored
  // flag stands in for the missing status endpoint.
  const active = has2fa || recoveryCodes !== null;

  return (
    <section className="panel">
      <div className="panel__head">
        <h2>
          <ShieldCheck size={15} aria-hidden="true" /> {t('security.title')}
        </h2>
        <p>{t('security.body')}</p>
      </div>

      {phase === 'idle' && !active ? (
        <div className="security__cta">
          <p className="panel__empty">{t('security.notEnrolled')}</p>
          <button type="button" className="btn btn--primary" onClick={startEnroll} disabled={busy}>
            {busy ? <Loader2 size={15} className="spin" aria-hidden="true" /> : <ShieldCheck size={15} aria-hidden="true" />}
            {t('security.startEnroll')}
          </button>
        </div>
      ) : null}

      {phase === 'enrolling' && secret !== null ? (
        <div className="security__enroll">
          <ol className="security__steps">
            <li>{t('security.stepScan')}</li>
            <li>{t('security.stepConfirm')}</li>
          </ol>
          <div className="security__secret">
            <code>{secret}</code>
            {otpauthUri !== null ? (
              <button type="button" className="btn btn--ghost btn--small" onClick={copyUri}>
                {copied ? <Check size={13} aria-hidden="true" /> : <Copy size={13} aria-hidden="true" />}
                {copied ? t('common.copied') : t('security.copyUri')}
              </button>
            ) : null}
          </div>
          <label className="field field--plain">
            <span className="field__label">{t('security.codeLabel')}</span>
            <input
              className="input"
              inputMode="numeric"
              autoComplete="one-time-code"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              placeholder="123456"
            />
          </label>
          {error !== null ? <p className="settings__error" role="alert"><AlertTriangle size={14} /> {error}</p> : null}
          <div className="security__actions">
            <button type="button" className="btn btn--primary" onClick={confirmActivate} disabled={busy || !code.trim()}>
              {busy ? <Loader2 size={15} className="spin" aria-hidden="true" /> : <ShieldCheck size={15} aria-hidden="true" />}
              {t('security.activate')}
            </button>
            <button
              type="button"
              className="btn btn--ghost"
              onClick={() => { setPhase('idle'); setSecret(null); setCode(''); }}
            >
              {t('common.cancel')}
            </button>
          </div>
        </div>
      ) : null}

      {phase === 'recovering' && recoveryCodes !== null ? (
        <div className="security__recovery">
          <p className="security__warn" role="status">
            <AlertTriangle size={14} aria-hidden="true" /> {t('security.recoveryOnce')}
          </p>
          <ul className="security__codes">
            {recoveryCodes.map((rc) => (
              <li key={rc}>
                <code>{rc}</code>
              </li>
            ))}
          </ul>
          <div className="security__actions">
            <button
              type="button"
              className="btn btn--primary"
              onClick={() => {
                void navigator.clipboard.writeText(recoveryCodes.join('\n'));
                notify('success', t('common.copied'));
              }}
            >
              <Copy size={15} aria-hidden="true" /> {t('security.copyCodes')}
            </button>
            <button type="button" className="btn btn--ghost" onClick={() => setPhase('idle')}>
              {t('security.done')}
            </button>
          </div>
        </div>
      ) : null}

      {phase === 'idle' && active ? (
        <div className="security__cta">
          <p className="panel__empty">
            <ShieldCheck size={14} aria-hidden="true" /> {t('security.activeNow')}
          </p>
          <div className="security__actions">
            <label className="field field--plain">
              <span className="field__label sr-only">{t('security.codeLabel')}</span>
              <input
                className="input"
                inputMode="numeric"
                value={code}
                onChange={(e) => setCode(e.target.value)}
                placeholder={t('security.codeLabel')}
              />
            </label>
            <button type="button" className="btn btn--ghost" onClick={stepUp} disabled={busy || !code.trim()}>
              {t('security.verify')}
            </button>
            <button type="button" className="btn btn--ghost" onClick={turnOff} disabled={busy || !code.trim()}>
              <ShieldOff size={14} aria-hidden="true" /> {t('security.disable')}
            </button>
          </div>
        </div>
      ) : null}
    </section>
  );
}

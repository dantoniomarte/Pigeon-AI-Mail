import { useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { AlertTriangle, CheckCircle2, Info, X } from 'lucide-react';

export type ToastKind = 'success' | 'error' | 'info';

export interface ToastItem {
  id: number;
  kind: ToastKind;
  message: string;
}

export interface ToastProps {
  items: ToastItem[];
  onDismiss: (id: number) => void;
}

const ICONS = {
  success: CheckCircle2,
  error: AlertTriangle,
  info: Info,
} as const;

function ToastRow({ item, onDismiss }: { item: ToastItem; onDismiss: (id: number) => void }): JSX.Element {
  const { t } = useTranslation();
  const Icon = ICONS[item.kind];

  useEffect(() => {
    const timer = window.setTimeout(() => onDismiss(item.id), 4200);
    return () => window.clearTimeout(timer);
  }, [item.id, onDismiss]);

  return (
    <div className={`toast toast--${item.kind}`} role={item.kind === 'error' ? 'alert' : 'status'}>
      <Icon size={17} aria-hidden="true" className="toast__icon" />
      <span className="toast__message">{item.message}</span>
      <button
        type="button"
        className="toast__close"
        onClick={() => onDismiss(item.id)}
        aria-label={t('common.close')}
      >
        <X size={14} />
      </button>
    </div>
  );
}

export default function Toast({ items, onDismiss }: ToastProps): JSX.Element {
  return (
    <div className="toasts" aria-live="polite" aria-atomic="false">
      {items.map((item) => (
        <ToastRow key={item.id} item={item} onDismiss={onDismiss} />
      ))}
    </div>
  );
}

import { useCallback, useEffect, useId, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  AlertTriangle,
  Bold,
  CalendarClock,
  Italic,
  Link2,
  List,
  ListOrdered,
  Loader2,
  Paperclip,
  PenLine,
  Save,
  Send,
  Strikethrough,
  Underline,
  Eraser,
  X,
} from 'lucide-react';

import {
  createDraft,
  fetchApiKeys,
  fetchTemplates,
  formatSize,
  sanitizeEmailHtml,
  sendDraft,
  sendEmail,
  textToHtml,
  updateDraft,
} from '../api';
import type { DraftPayload, SendPayload, Template } from '../api';
import type { ComposeSeed } from '../App';
import type { ToastKind } from './Toast';

export interface ComposeProps {
  apiKey: string | null;
  seed: ComposeSeed;
  onClose: () => void;
  onSent: (from: string) => void;
  /** Fired after a draft was saved, so the Drafts view can refresh. */
  onDraftSaved: () => void;
  notify: (kind: ToastKind, message: string) => void;
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/** Server limits (docs/API.md): ≤ 10 attachments, ≤ 25 MB decoded total. */
const MAX_ATTACHMENTS = 10;
const MAX_TOTAL_BYTES = 25 * 1024 * 1024;
/** Server limit: ≤ 10 tags, each `[a-z0-9-]{1,40}`. */
const MAX_TAGS = 10;
const TAG_RE = /^[a-z0-9-]{1,40}$/;

function parseAddresses(value: string): string[] {
  return value
    .split(/[,;\n]/)
    .map((part) => part.trim())
    .filter((part) => part.length > 0);
}

// ------------------------------------------------------------- attachments

interface PendingAttachment {
  id: number;
  filename: string;
  size: number;
  /** base64 payload, dataURL prefix stripped. */
  content: string;
}

/** Read a file as base64, dropping the `data:…;base64,` prefix. */
function readAsBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const result = typeof reader.result === 'string' ? reader.result : '';
      const comma = result.indexOf(',');
      if (comma === -1) {
        reject(new Error('unreadable file'));
        return;
      }
      resolve(result.slice(comma + 1));
    };
    reader.onerror = () => {
      reject(reader.error ?? new Error('unreadable file'));
    };
    reader.readAsDataURL(file);
  });
}

/** Decoded byte count of a base64 payload, so a continued draft shows real sizes. */
function base64Size(content: string): number {
  const padding = content.endsWith('==') ? 2 : content.endsWith('=') ? 1 : 0;
  return Math.max(0, Math.floor((content.length * 3) / 4) - padding);
}

// ------------------------------------------------------------- scheduling

function pad2(value: number): string {
  return String(value).padStart(2, '0');
}

/** `datetime-local` value for "right now" in the browser's timezone. */
function nowAsLocalInput(): string {
  const now = new Date();
  return `${now.getFullYear()}-${pad2(now.getMonth() + 1)}-${pad2(now.getDate())}T${pad2(now.getHours())}:${pad2(now.getMinutes())}`;
}

/** Sensible default when the schedule toggle is switched on: one hour from now. */
function inOneHourAsLocalInput(): string {
  const when = new Date(Date.now() + 60 * 60 * 1000);
  return `${when.getFullYear()}-${pad2(when.getMonth() + 1)}-${pad2(when.getDate())}T${pad2(when.getHours())}:${pad2(when.getMinutes())}`;
}

function browserTimeZone(): string {
  try {
    const zone = Intl.DateTimeFormat().resolvedOptions().timeZone;
    return zone.length > 0 ? zone : 'local time';
  } catch {
    return 'local time';
  }
}

// ------------------------------------------------------------- rich-text toolbar

interface ToolbarButton {
  cmd: string;
  icon: JSX.Element;
  /** i18n key, resolved at render so the label follows the active language. */
  labelKey: string;
  separatorBefore?: boolean;
}

const TOOLBAR_BUTTONS: ToolbarButton[] = [
  { cmd: 'bold', icon: <Bold size={15} />, labelKey: 'compose.toolbar.bold' },
  { cmd: 'italic', icon: <Italic size={15} />, labelKey: 'compose.toolbar.italic' },
  { cmd: 'underline', icon: <Underline size={15} />, labelKey: 'compose.toolbar.underline' },
  { cmd: 'strikeThrough', icon: <Strikethrough size={15} />, labelKey: 'compose.toolbar.strikeThrough' },
  {
    cmd: 'insertUnorderedList',
    icon: <List size={15} />,
    labelKey: 'compose.toolbar.bulletedList',
    separatorBefore: true,
  },
  { cmd: 'insertOrderedList', icon: <ListOrdered size={15} />, labelKey: 'compose.toolbar.numberedList' },
  { cmd: 'createLink', icon: <Link2 size={15} />, labelKey: 'compose.toolbar.insertLink', separatorBefore: true },
  { cmd: 'removeFormat', icon: <Eraser size={15} />, labelKey: 'compose.toolbar.clearFormatting' },
];

function RichTextToolbar({ editorRef }: { editorRef: React.RefObject<HTMLDivElement | null> }): JSX.Element {
  const { t } = useTranslation();
  const [active, setActive] = useState<Record<string, boolean>>({});

  const update = useCallback(() => {
    const state: Record<string, boolean> = {};
    for (const btn of TOOLBAR_BUTTONS) {
      try { state[btn.cmd] = document.queryCommandState(btn.cmd); } catch { state[btn.cmd] = false; }
    }
    setActive(state);
  }, []);

  const exec = useCallback((cmd: string) => {
    editorRef.current?.focus();
    if (cmd === 'createLink') {
      const url = window.prompt(t('compose.toolbar.linkPrompt'), 'https://');
      if (url && url !== 'https://') document.execCommand('createLink', false, url);
    } else {
      document.execCommand(cmd, false, undefined);
    }
    update();
  }, [editorRef, t, update]);

  return (
    <div className="rtb" role="toolbar" aria-label={t('compose.toolbar.label')} onMouseDown={e => e.preventDefault()}>
      {TOOLBAR_BUTTONS.map((btn) => {
        const label = t(btn.labelKey);
        return (
          <span key={btn.cmd} className={btn.separatorBefore ? 'rtb__sep-wrap' : undefined}>
            {btn.separatorBefore ? <span className="rtb__sep" aria-hidden="true" /> : null}
            <button
              type="button"
              className={`rtb__btn${active[btn.cmd] ? ' rtb__btn--active' : ''}`}
              onMouseDown={e => e.preventDefault()}
              onClick={() => exec(btn.cmd)}
              aria-label={label}
              title={label}
            >
              {btn.icon}
            </button>
          </span>
        );
      })}
    </div>
  );
}

export default function Compose({
  apiKey,
  seed,
  onClose,
  onSent,
  onDraftSaved,
  notify,
}: ComposeProps): JSX.Element {
  const { t, i18n } = useTranslation();
  const fromId = useId();
  const toId = useId();
  const ccId = useId();
  const subjectId = useId();
  const bodyId = useId();
  const tagsId = useId();
  const scheduleId = useId();

  const [from, setFrom] = useState(seed.from);
  const [to, setTo] = useState(seed.to);
  const [cc, setCc] = useState(seed.cc ?? '');
  const [showCc, setShowCc] = useState((seed.cc ?? '').trim().length > 0);
  const [subject, setSubject] = useState(seed.subject);
  const [sending, setSending] = useState(false);
  const [savingDraft, setSavingDraft] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [attachments, setAttachments] = useState<PendingAttachment[]>(() =>
    (seed.attachments ?? []).map((file, index) => ({
      id: index + 1,
      filename: file.filename,
      size: base64Size(file.content),
      content: file.content,
    })),
  );
  const [tagInput, setTagInput] = useState('');
  const [tags, setTags] = useState<string[]>(seed.tags ?? []);
  const [scheduleEnabled, setScheduleEnabled] = useState(false);
  const [scheduleAt, setScheduleAt] = useState('');
  const [sandbox, setSandbox] = useState(false);
  // The stored draft this box belongs to, when it was opened from `Drafts`.
  // Saving twice updates the same row instead of piling up copies, and sending
  // goes through `/v1/drafts/{id}/send` so the draft is consumed server-side.
  const [draftId, setDraftId] = useState<string | null>(seed.draftId ?? null);
  const [templates, setTemplates] = useState<Template[]>([]);

  const toRef = useRef<HTMLInputElement>(null);
  const bodyRef = useRef<HTMLDivElement>(null);
  const formRef = useRef<HTMLFormElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const attachmentSeq = useRef((seed.attachments ?? []).length);

  // Set initial rich-text content once (contentEditable is uncontrolled).
  // The body arrives from the API (a stored draft or a template), so it is
  // sanitised here: this is the sink that would otherwise execute its scripts.
  const initialised = useRef(false);
  useEffect(() => {
    if (!initialised.current && bodyRef.current) {
      bodyRef.current.innerHTML = sanitizeEmailHtml(seed.body || '');
      initialised.current = true;
    }
  }, [seed.body]);

  useEffect(() => {
    if (seed.to.length > 0) {
      bodyRef.current?.focus();
    } else {
      toRef.current?.focus();
    }
  }, [seed.to]);

  // Best-effort sandbox detection: the key list never exposes key material, so we
  // cannot match this session's `pk_` prefix. If any live key on the account is a
  // sandbox key, warn in the compose header; a failed fetch stays silent.
  useEffect(() => {
    let cancelled = false;
    void fetchApiKeys(apiKey)
      .then((keys) => {
        if (!cancelled) {
          setSandbox(keys.some((entry) => entry.sandbox === true && entry.revoked !== true));
        }
      })
      .catch(() => {
        // Sandbox detection is a nicety; never surface its failure.
      });
    return () => {
      cancelled = true;
    };
  }, [apiKey]);

  // Templates feed the "use template" picker. A failure is silent: composing
  // without templates must still work.
  useEffect(() => {
    let cancelled = false;
    void fetchTemplates(apiKey)
      .then((list) => {
        if (!cancelled) {
          setTemplates(list);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setTemplates([]);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [apiKey]);

  const addAttachments = useCallback(
    (picked: FileList | null) => {
      // Snapshot the files before clearing the input: resetting `value` empties
      // the live FileList, and the same input must stay reusable.
      const files = picked === null ? [] : Array.from(picked);
      if (fileInputRef.current !== null) {
        fileInputRef.current.value = '';
      }
      if (files.length === 0) {
        return;
      }

      const slots = MAX_ATTACHMENTS - attachments.length;
      if (slots <= 0) {
        setError(t('compose.tooManyFiles'));
        return;
      }

      // Validate the cap and the total size before reading anything.
      let total = attachments.reduce((sum, file) => sum + file.size, 0);
      let capError: string | null = null;
      const chosen: File[] = [];
      for (const file of files) {
        if (chosen.length >= slots) {
          capError = t('compose.tooManyFiles');
          break;
        }
        if (total + file.size > MAX_TOTAL_BYTES) {
          capError = t('compose.tooLarge');
          break;
        }
        total += file.size;
        chosen.push(file);
      }
      if (chosen.length === 0) {
        setError(capError ?? t('compose.tooLarge'));
        return;
      }

      void (async () => {
        const accepted: PendingAttachment[] = [];
        let failed = false;
        for (const file of chosen) {
          try {
            const content = await readAsBase64(file);
            attachmentSeq.current += 1;
            accepted.push({ id: attachmentSeq.current, filename: file.name, size: file.size, content });
          } catch {
            failed = true;
          }
        }
        if (accepted.length > 0) {
          setAttachments((current) => [...current, ...accepted]);
        }
        setError(capError ?? (failed ? t('compose.attachFailed') : null));
      })();
    },
    [attachments, t],
  );

  const removeAttachment = useCallback((id: number) => {
    setAttachments((current) => current.filter((file) => file.id !== id));
  }, []);

  const addTag = useCallback(() => {
    const candidate = tagInput.trim().toLowerCase();
    setTagInput('');
    // Invalid characters, over-long tokens and extras past the server cap are
    // dropped silently; the send payload only ever carries valid tags.
    if (!TAG_RE.test(candidate)) {
      return;
    }
    setTags((current) => (current.includes(candidate) || current.length >= MAX_TAGS ? current : [...current, candidate]));
  }, [tagInput]);

  const removeTag = useCallback((tag: string) => {
    setTags((current) => current.filter((entry) => entry !== tag));
  }, []);

  // Both halves of the editor content, read the same way for send and save.
  const collectBody = useCallback(() => {
    const bodyEl = bodyRef.current;
    const html = bodyEl ? bodyEl.innerHTML.trim() : '';
    const text = bodyEl ? bodyEl.innerText.trim() : '';
    return { html, text: text || html };
  }, []);

  /**
   * The draft payload this box currently holds, shared by the manual save and
   * the save-on-close below.
   */
  const buildDraftPayload = useCallback((): DraftPayload => {
    const { html, text } = collectBody();
    return {
      from: from.trim(),
      to: parseAddresses(to),
      cc: parseAddresses(cc),
      subject: subject.trim(),
      html,
      text,
      attachments: attachments.map((file) => ({ filename: file.filename, content: file.content })),
      tags,
    };
  }, [attachments, cc, collectBody, from, subject, tags, to]);

  /** True when closing would throw away something the user typed or attached. */
  const hasContent = useCallback((): boolean => {
    const bodyEl = bodyRef.current;
    const typedBody = bodyEl !== null ? bodyEl.innerText.trim() : '';
    return (
      typedBody.length > 0 ||
      subject.trim().length > 0 ||
      parseAddresses(to).length > 0 ||
      parseAddresses(cc).length > 0 ||
      attachments.length > 0 ||
      tags.length > 0
    );
  }, [attachments.length, cc, subject, tags.length, to]);

  /**
   * Every exit (Escape, the X, Cancel, a backdrop click) runs through here.
   *
   * If the box holds anything, a draft save is fired first and **not awaited**:
   * closing stays instant and is never blocked by a prompt or a spinner. The
   * toast reports the outcome after the overlay is already gone. A save that is
   * already in flight is left to finish instead of being duplicated.
   */
  const close = useCallback(() => {
    if (sending) {
      return;
    }
    if (hasContent() && !savingDraft) {
      const saving = draftId === null ? createDraft(apiKey, buildDraftPayload()) : updateDraft(apiKey, draftId, buildDraftPayload());
      void saving
        .then(() => {
          notify('success', t('drafts.saved'));
          onDraftSaved();
        })
        .catch(() => notify('error', t('compose.draftSaveFailed')));
    }
    onClose();
  }, [apiKey, buildDraftPayload, draftId, hasContent, notify, onClose, onDraftSaved, savingDraft, sending, t]);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        close();
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [close]);

  /**
   * Save the current box as a draft. Manual save: the first save creates the
   * draft and remembers its id, later saves patch the same row.
   */
  const saveDraft = useCallback(() => {
    if (savingDraft || sending) {
      return;
    }
    setSavingDraft(true);
    const payload = buildDraftPayload();
    const saved = draftId === null ? createDraft(apiKey, payload) : updateDraft(apiKey, draftId, payload);
    void saved
      .then((draft) => {
        setDraftId(draft.id);
        setSavingDraft(false);
        notify('success', t('drafts.saved'));
        onDraftSaved();
      })
      .catch(() => {
        setSavingDraft(false);
        notify('error', t('common.error'));
      });
  }, [apiKey, buildDraftPayload, draftId, notify, onDraftSaved, savingDraft, sending, t]);

  /** Render a stored template into the subject and the editor. */
  const applyTemplate = useCallback(
    (id: string) => {
      const chosen = templates.find((entry) => entry.id === id);
      if (chosen === undefined) {
        return;
      }
      const editor = bodyRef.current;
      const hasContent =
        editor !== null && (editor.innerText.trim().length > 0 || editor.innerHTML.trim().length > 0);
      if (hasContent && !window.confirm(t('compose.confirmReplace'))) {
        return;
      }
      if (editor !== null) {
        const html = (chosen.html ?? '').trim();
        // Template HTML is API data from a shared account: sanitise at the sink.
        editor.innerHTML = sanitizeEmailHtml(html.length > 0 ? html : textToHtml(chosen.text ?? ''));
      }
      const templateSubject = (chosen.subject ?? '').trim();
      if (templateSubject.length > 0) {
        setSubject(templateSubject);
      }
    },
    [t, templates],
  );

  const submit = useCallback(
    (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      // A save in flight would write the pre-send box over the draft the send is
      // about to consume, so sending waits for it to finish.
      if (sending || savingDraft) {
        return;
      }
      const sender = from.trim();
      const recipients = parseAddresses(to);
      const copies = parseAddresses(cc);

      if (sender.length === 0) {
        setError(t('compose.requiredFrom'));
        return;
      }
      if (!EMAIL_RE.test(sender)) {
        setError(t('compose.invalidEmail'));
        return;
      }
      if (recipients.length === 0) {
        setError(t('compose.requiredTo'));
        return;
      }
      if (recipients.some((address) => !EMAIL_RE.test(address)) || copies.some((address) => !EMAIL_RE.test(address))) {
        setError(t('compose.invalidEmail'));
        return;
      }

      let scheduledAtIso: string | null = null;
      if (scheduleEnabled) {
        const when = new Date(scheduleAt);
        if (scheduleAt.trim().length === 0 || Number.isNaN(when.getTime()) || when.getTime() <= Date.now()) {
          setError(t('compose.scheduleFuture'));
          return;
        }
        scheduledAtIso = when.toISOString();
      }

      setError(null);
      setSending(true);

      // Extract both rich (html) and plain-text from the contentEditable body.
      const { html, text } = collectBody();

      const payload: SendPayload = {
        from: sender,
        to: recipients,
        ...(copies.length > 0 ? { cc: copies } : {}),
        subject: subject.trim(),
        html: html || undefined,
        text: text || html,
        ...(attachments.length > 0
          ? { attachments: attachments.map((file) => ({ filename: file.filename, content: file.content })) }
          : {}),
        ...(tags.length > 0 ? { tags } : {}),
        ...(scheduledAtIso !== null ? { scheduled_at: scheduledAtIso } : {}),
      };

      // Continuing a draft sends it through the draft endpoint, which consumes
      // the stored row only after the email was accepted.
      const dispatched = draftId === null ? sendEmail(apiKey, payload) : sendDraft(apiKey, draftId);
      void dispatched
        .then(() => {
          onSent(sender);
        })
        .catch(() => {
          setSending(false);
          setError(t('compose.sendError'));
          notify('error', t('toast.sendFailed'));
        });
    },
    [
      apiKey,
      attachments,
      cc,
      collectBody,
      draftId,
      from,
      notify,
      onSent,
      scheduleAt,
      scheduleEnabled,
      savingDraft,
      sending,
      subject,
      t,
      tags,
      to,
    ],
  );

  const sendLabel = scheduleEnabled ? t('compose.schedule') : t('compose.send');

  return (
    <div className="compose-overlay" role="presentation" onMouseDown={(event) => {
      if (event.target === event.currentTarget) {
        close();
      }
    }}>
      <div className="compose" role="dialog" aria-modal="true" aria-labelledby="compose-title">
        <header className="compose__head">
          <span className="compose__glyph" aria-hidden="true">
            <PenLine size={17} />
          </span>
          <h2 className="compose__title" id="compose-title">
            {t('compose.title')}
          </h2>
          {sandbox ? (
            <span className="compose__sandbox" title={t('compose.sandboxNotice')}>
              <span className="compose__sandbox-emoji" aria-hidden="true">
                🧪
              </span>
              <span className="compose__sandbox-text">{t('compose.sandboxNotice')}</span>
            </span>
          ) : null}
          <button type="button" className="icon-btn" onClick={close} aria-label={t('common.close')} disabled={sending}>
            <X size={17} />
          </button>
        </header>

        <form className="compose__form" ref={formRef} onSubmit={submit}>
          <div className="compose__rows">
            <div className="compose__row">
              <label className="compose__label" htmlFor={fromId}>
                {t('compose.from')}
              </label>
              <input
                id={fromId}
                className="compose__input"
                type="email"
                autoComplete="email"
                placeholder={t('compose.fromPlaceholder')}
                value={from}
                onChange={(event) => setFrom(event.target.value)}
              />
            </div>

            <div className="compose__row">
              <label className="compose__label" htmlFor={toId}>
                {t('compose.to')}
              </label>
              <div className="compose__row-control">
                <input
                  id={toId}
                  ref={toRef}
                  className="compose__input"
                  type="text"
                  autoComplete="off"
                  placeholder={t('compose.toPlaceholder')}
                  value={to}
                  onChange={(event) => setTo(event.target.value)}
                />
                {!showCc ? (
                  <button type="button" className="compose__cc-toggle" onClick={() => setShowCc(true)}>
                    {t('compose.ccToggle')}
                  </button>
                ) : null}
              </div>
            </div>

            {showCc ? (
              <div className="compose__row">
                <label className="compose__label" htmlFor={ccId}>
                  {t('compose.cc')}
                </label>
                <input
                  id={ccId}
                  className="compose__input"
                  type="text"
                  autoComplete="off"
                  placeholder={t('compose.toPlaceholder')}
                  value={cc}
                  onChange={(event) => setCc(event.target.value)}
                />
              </div>
            ) : null}

            <div className="compose__row">
              <label className="compose__label" htmlFor={subjectId}>
                {t('compose.subject')}
              </label>
              <input
                id={subjectId}
                className="compose__input compose__input--subject"
                type="text"
                placeholder={t('compose.subjectPlaceholder')}
                value={subject}
                onChange={(event) => setSubject(event.target.value)}
              />
            </div>

            <div className="compose__row">
              <label className="compose__label" htmlFor={tagsId}>
                {t('compose.tags')}
              </label>
              <div className="tags">
                {tags.map((tag) => (
                  <span className="tag" key={tag}>
                    {tag}
                    <button
                      type="button"
                      className="tag__x"
                      onClick={() => removeTag(tag)}
                      aria-label={`${t('compose.removeTag')}: ${tag}`}
                      title={t('compose.removeTag')}
                      disabled={sending}
                    >
                      <X size={10} />
                    </button>
                  </span>
                ))}
                <input
                  id={tagsId}
                  className="tags__input"
                  type="text"
                  autoComplete="off"
                  spellCheck={false}
                  placeholder={tags.length === 0 ? t('compose.tagsPlaceholder') : undefined}
                  value={tagInput}
                  onChange={(event) => setTagInput(event.target.value)}
                  onKeyDown={(event) => {
                    if (event.key === 'Enter' || event.key === ',') {
                      event.preventDefault();
                      addTag();
                    } else if (event.key === 'Backspace' && tagInput.length === 0 && tags.length > 0) {
                      event.preventDefault();
                      removeTag(tags[tags.length - 1] ?? '');
                    }
                  }}
                  onBlur={() => {
                    if (tagInput.trim().length > 0) {
                      addTag();
                    }
                  }}
                />
              </div>
            </div>
          </div>

          <div className="compose__body">
            <label className="sr-only" htmlFor={bodyId}>
              {t('compose.body')}
            </label>
            <div className="compose__toolbar">
              <RichTextToolbar editorRef={bodyRef} />
              {templates.length > 0 ? (
                <select
                  className="compose__tpl"
                  aria-label={t('compose.useTemplate')}
                  title={t('compose.useTemplate')}
                  value=""
                  disabled={sending}
                  onChange={(event) => applyTemplate(event.target.value)}
                >
                  <option value="">{t('compose.useTemplate')}</option>
                  {templates.map((entry) => (
                    <option key={entry.id} value={entry.id}>
                      {entry.description !== undefined && entry.description.length > 0
                        ? `${entry.name} — ${entry.description}`
                        : entry.name}
                    </option>
                  ))}
                </select>
              ) : null}
            </div>
            <div
              id={bodyId}
              ref={bodyRef}
              className="compose__editor"
              contentEditable
              suppressContentEditableWarning
              role="textbox"
              aria-multiline="true"
              aria-label={t('compose.body')}
              data-placeholder={t('compose.bodyPlaceholder')}
              onKeyDown={(event) => {
                if (event.key === 'Enter' && (event.metaKey || event.ctrlKey)) {
                  event.preventDefault();
                  formRef.current?.requestSubmit();
                }
              }}
            />
          </div>

          {attachments.length > 0 ? (
            <ul className="compose__attach-list" aria-label={t('compose.attachments')}>
              {attachments.map((file) => (
                <li className="attach-chip" key={file.id}>
                  <Paperclip size={12} aria-hidden="true" className="attach-chip__icon" />
                  <span className="attach-chip__name" title={file.filename}>
                    {file.filename}
                  </span>
                  <span className="attach-chip__size">{formatSize(file.size, i18n.language)}</span>
                  <button
                    type="button"
                    className="attach-chip__x"
                    onClick={() => removeAttachment(file.id)}
                    aria-label={`${t('compose.removeAttachment')}: ${file.filename}`}
                    title={t('compose.removeAttachment')}
                    disabled={sending}
                  >
                    <X size={11} />
                  </button>
                </li>
              ))}
            </ul>
          ) : null}

          {scheduleEnabled ? (
            <div className="compose__schedule">
              <label className="compose__schedule-label" htmlFor={scheduleId}>
                <CalendarClock size={13} aria-hidden="true" />
                {t('compose.scheduleAt')}
              </label>
              <input
                id={scheduleId}
                className="compose__schedule-input"
                type="datetime-local"
                min={nowAsLocalInput()}
                value={scheduleAt}
                onChange={(event) => setScheduleAt(event.target.value)}
                disabled={sending}
              />
              <span className="compose__schedule-tz">{t('compose.scheduleHint', { tz: browserTimeZone() })}</span>
            </div>
          ) : null}

          {error !== null ? (
            <p className="compose__error" role="alert">
              <AlertTriangle size={14} aria-hidden="true" />
              {error}
            </p>
          ) : null}

          <footer className="compose__foot">
            <div className="compose__foot-tools">
              <input
                ref={fileInputRef}
                type="file"
                multiple
                className="sr-only"
                tabIndex={-1}
                aria-hidden="true"
                onChange={(event) => {
                  addAttachments(event.target.files);
                }}
              />
              <button
                type="button"
                className="compose__tool"
                onClick={() => fileInputRef.current?.click()}
                aria-label={t('compose.addAttachment')}
                title={t('compose.addAttachment')}
                disabled={sending}
              >
                <Paperclip size={15} aria-hidden="true" />
                {attachments.length > 0 ? <span className="compose__tool-count">{attachments.length}</span> : null}
              </button>
              <span className="compose__hint">{t('compose.hint')}</span>
            </div>
            <div className="compose__foot-actions">
              <button
                type="button"
                className={`compose__tool${scheduleEnabled ? ' compose__tool--on' : ''}`}
                onClick={() => {
                  const next = !scheduleEnabled;
                  setScheduleEnabled(next);
                  if (next && scheduleAt.length === 0) {
                    setScheduleAt(inOneHourAsLocalInput());
                  }
                }}
                aria-pressed={scheduleEnabled}
                aria-label={t('compose.schedule')}
                title={scheduleEnabled ? t('compose.sendNow') : t('compose.schedule')}
                disabled={sending}
              >
                <CalendarClock size={15} aria-hidden="true" />
              </button>
              <button type="button" className="btn btn--ghost" onClick={close} disabled={sending}>
                {t('common.cancel')}
              </button>
              <button
                type="button"
                className="btn btn--ghost"
                onClick={saveDraft}
                disabled={sending || savingDraft}
              >
                {savingDraft ? (
                  <Loader2 size={15} aria-hidden="true" className="spin" />
                ) : (
                  <Save size={15} aria-hidden="true" />
                )}
                {t('compose.saveDraft')}
              </button>
              <button type="submit" className="btn btn--primary" disabled={sending || savingDraft}>
                {sending ? (
                  <Loader2 size={16} aria-hidden="true" className="spin" />
                ) : scheduleEnabled ? (
                  <CalendarClock size={16} aria-hidden="true" />
                ) : (
                  <Send size={16} aria-hidden="true" />
                )}
                {sending ? t('compose.sending') : sendLabel}
              </button>
            </div>
          </footer>
        </form>
      </div>
    </div>
  );
}

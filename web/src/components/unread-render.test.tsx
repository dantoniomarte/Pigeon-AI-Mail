import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';

import MailList, { type MailListProps } from './MailList';
import MailView from './MailView';
import type { MessageDetail } from '../api';

function mailListProps(items: MailListProps['items']): MailListProps {
  return {
    view: 'inbox',
    items,
    state: 'ready',
    selectedId: null,
    demo: false,
    onRetry: vi.fn(),
    onCompose: vi.fn(),
    onSelect: vi.fn(),
    onMarkRead: vi.fn(),
    onMove: vi.fn(),
    onDelete: vi.fn(),
  };
}

describe('unread row affordance', () => {
  it('marks unread rows with the unread class and a labelled dot', () => {
    render(
      <MailList
        {...mailListProps([
          {
            id: 'row-unread',
            from: 'Mara Alvarez <mara@estudio-norte.com>',
            subject: 'Unread report',
            createdAt: null,
            preview: 'Numbers inside',
            unread: true,
            encrypted: false,
          },
          {
            id: 'row-read',
            from: 'Bruno Diaz <bruno@estudio-norte.com>',
            subject: 'Read receipt',
            createdAt: null,
            preview: 'Already seen',
            unread: false,
            encrypted: false,
          },
        ])}
      />,
    );

    const unreadRow = screen.getByText('Unread report').closest('button');
    expect(unreadRow).not.toBeNull();
    expect(unreadRow?.classList.contains('is-unread')).toBe(true);
    const unreadDot = within(unreadRow as HTMLElement).getByRole('img', { name: 'Unread' });
    // Prominent placement: the dot sits in the top line next to the time,
    // not buried in the bottom badge row.
    expect(unreadDot.closest('.mail-row__top')).not.toBeNull();

    const readRow = screen.getByText('Read receipt').closest('button');
    expect(readRow?.classList.contains('is-unread')).toBe(false);
    expect(within(readRow as HTMLElement).queryByRole('img', { name: 'Unread' })).not.toBeInTheDocument();
  });
});

function messageFixture(partial: Partial<MessageDetail>): MessageDetail {
  return {
    id: 'msg-1',
    from_addr: 'Mara Alvarez <mara@estudio-norte.com>',
    subject: 'Quarterly numbers',
    created_at: '2026-02-03T10:00:00Z',
    read: false,
    ...partial,
  };
}

function mailViewProps(): Parameters<typeof MailView>[0] {
  return {
    mode: 'mail',
    message: null,
    state: 'ready',
    demo: false,
    onBack: vi.fn(),
    onReply: vi.fn(),
    onForward: vi.fn(),
    onRetry: vi.fn(),
  };
}

describe('html message rendering', () => {
  it('renders an html body inside a sandboxed frame, never flattened text', () => {
    const props = mailViewProps();
    props.message = messageFixture({ body_html: '<h2>Title</h2><p>Body copy</p>' });
    render(<MailView {...props} />);

    const frame = screen.getByTitle('Message body');
    expect(frame.tagName).toBe('IFRAME');
    const sandbox = frame.getAttribute('sandbox') ?? '';
    expect(sandbox).toContain('allow-popups');
    expect(sandbox).not.toContain('allow-scripts');
    expect(sandbox).not.toContain('allow-same-origin');

    const doc = frame.getAttribute('srcdoc') ?? '';
    expect(doc).toContain('Content-Security-Policy');
    expect(doc).toContain('<base target="_blank">');
    expect(doc).toContain('<h2>Title</h2>');

    // Remote images start blocked, with an explicit action to load them.
    expect(doc).toContain('img-src data: blob:');
    expect(doc).not.toContain('img-src https:');
    expect(screen.getByRole('button', { name: 'Load images' })).toBeInTheDocument();

    // The old "text was extracted" fallback must be gone for html bodies.
    expect(screen.queryByText(/extracted for safe reading/)).not.toBeInTheDocument();
  });

  it('rebuilds the frame with remote images allowed after the explicit action', async () => {
    const user = userEvent.setup();
    const props = mailViewProps();
    props.message = messageFixture({ body_html: '<img src="https://cdn.example/pic.png" alt="pic">' });
    render(<MailView {...props} />);

    expect(screen.getByTitle('Message body').getAttribute('srcdoc')).not.toContain('img-src https:');
    await user.click(screen.getByRole('button', { name: 'Load images' }));
    expect(screen.getByTitle('Message body').getAttribute('srcdoc')).toContain('img-src https: http:');
    expect(screen.getByRole('button', { name: 'Block images' })).toBeInTheDocument();
  });

  it('prefers the html part when both text and html exist', () => {
    const props = mailViewProps();
    props.message = messageFixture({
      body_text: 'See https://ejemplo.com/a',
      body_html: '<p>Styled body</p>',
    });
    render(<MailView {...props} />);

    expect(screen.getByTitle('Message body')).toBeInTheDocument();
    expect(screen.queryByRole('link')).not.toBeInTheDocument();
  });
});

describe('plain-text message rendering', () => {
  it('renders no frame and turns urls into safe links', () => {
    const props = mailViewProps();
    props.message = messageFixture({
      body_text: 'Hola, mirá https://ejemplo.com/repo?x=1 y avisame.\n\nChau!',
    });
    render(<MailView {...props} />);

    expect(screen.queryByTitle('Message body')).not.toBeInTheDocument();
    const link = screen.getByRole('link', { name: 'https://ejemplo.com/repo?x=1' });
    expect(link.getAttribute('href')).toBe('https://ejemplo.com/repo?x=1');
    expect(link.getAttribute('target')).toBe('_blank');
    expect(link.getAttribute('rel')).toContain('noreferrer');
    expect(screen.getByText('Chau!')).toBeInTheDocument();
  });
});

describe('theme-aware email frame', () => {
  it('renders the dark scheme inside the frame when the app is dark', () => {
    const props = mailViewProps();
    props.scheme = 'dark';
    props.message = messageFixture({ body_html: '<p>styled by provider</p>' });
    render(<MailView {...props} />);

    const doc = screen.getByTitle('Message body').getAttribute('srcdoc') ?? '';
    expect(doc).toContain('pigeon-dark-email');
    expect(doc).toContain('color-scheme:dark');
    // Legibility: the universal rule forces a light color directly (never
    // `inherit`), so dark text painted by the email cannot survive on the
    // darkened background.
    expect(doc).toContain('color:#e6edf3!important');
    expect(doc).not.toContain('color:inherit!important');
    // Links stay recognizable.
    expect(doc).toContain('a{color:#6cb2ff!important');
    // The provider markup itself is untouched.
    expect(doc).toContain('<p>styled by provider</p>');
  });

  it('keeps the light canvas by default', () => {
    const props = mailViewProps();
    props.message = messageFixture({ body_html: '<p>light mail</p>' });
    render(<MailView {...props} />);
    const doc = screen.getByTitle('Message body').getAttribute('srcdoc') ?? '';
    expect(doc).toContain('html{background:#fff}');
    expect(doc).not.toContain('pigeon-dark-email');
  });
});

describe('selected row vs unread row', () => {
  it('marks the opened row as selected, a separate visual state from unread', () => {
    const props = mailListProps([
      {
        id: 'row-open',
        from: 'Ines Duarte <ines@duarte.dev>',
        subject: 'Reading now',
        createdAt: null,
        preview: null,
        unread: false,
        encrypted: false,
      },
      {
        id: 'row-other',
        from: 'Tomas Lindqvist <tomas@northlight.se>',
        subject: 'Still unread',
        createdAt: null,
        preview: null,
        unread: true,
        encrypted: false,
      },
    ]);
    props.selectedId = 'row-open';
    render(<MailList {...props} />);

    const open = screen.getByText('Reading now').closest('button');
    const unread = screen.getByText('Still unread').closest('button');
    expect(open?.classList.contains('is-selected')).toBe(true);
    expect(open?.classList.contains('is-unread')).toBe(false);
    expect(unread?.classList.contains('is-selected')).toBe(false);
    expect(unread?.classList.contains('is-unread')).toBe(true);
    expect(within(unread as HTMLElement).getByRole('img', { name: 'Unread' })).toBeInTheDocument();
    expect(within(open as HTMLElement).queryByRole('img', { name: 'Unread' })).not.toBeInTheDocument();
  });
});

describe('dark scheme sender paint neutralization', () => {
  it('strips sender inline color/background declarations in dark mode', () => {
    const props = mailViewProps();
    props.scheme = 'dark';
    props.message = messageFixture({
      body_html:
        '<div style="background:#0f6b5c"><p style="color:#fff!important">invisible risk</p></div>' +
        '<h1 style="background:linear-gradient(#0f6b5c,#14876f);-webkit-background-clip:text;-webkit-text-fill-color:transparent">headline</h1>',
    });
    render(<MailView {...props} />);

    const doc = screen.getByTitle('Message body').getAttribute('srcdoc') ?? '';
    // No sender paint values survive in dark mode (JD-B-002 / JD-B-003).
    expect(doc).not.toMatch(/color\s*:\s*#fff/i);
    expect(doc).not.toContain('#0f6b5c');
    expect(doc).not.toContain('-webkit-text-fill-color:transparent');
    // The markup and text remain.
    expect(doc).toContain('invisible risk');
    expect(doc).toContain('headline');
    // The lifted palette rule is present.
    expect(doc).toContain('color:#e6edf3!important');
  });

  it('keeps sender inline styles untouched in light mode', () => {
    const props = mailViewProps();
    props.message = messageFixture({ body_html: '<p style="color:#fff!important;background:#0f6b5c">styled</p>' });
    render(<MailView {...props} />);
    const doc = screen.getByTitle('Message body').getAttribute('srcdoc') ?? '';
    expect(doc).toContain('#0f6b5c');
  });
});

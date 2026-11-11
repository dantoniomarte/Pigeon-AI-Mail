import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';

import MailList, { type MailListProps } from './MailList';
import MailView from './MailView';

const bulkOutcome = (): Promise<{ applied: string[]; failed: string[] }> =>
  Promise.resolve({ applied: [], failed: [] });

function mailListProps(view: 'inbox' | 'sent'): MailListProps {
  return {
    view,
    items: [
      {
        id: 'row-1',
        from: 'Mara Alvarez <mara@estudio-norte.com>',
        subject: 'Cover final',
        createdAt: null,
        preview: null,
        unread: view === 'inbox',
        encrypted: true,
      },
    ],
    state: 'ready',
    selectedId: null,
    demo: false,
    onRetry: vi.fn(),
    onCompose: vi.fn(),
    onSelect: vi.fn(),
    onMarkRead: vi.fn(),
    onMove: vi.fn(),
    onDelete: vi.fn(),
    onMarkReadBulk: vi.fn(bulkOutcome),
    onMoveBulk: vi.fn(bulkOutcome),
    onDeleteBulk: vi.fn(bulkOutcome),
  };
}

describe('sent folder deletion', () => {
  it('lets sent rows be selected and offers delete only in bulk', async () => {
    const user = userEvent.setup();
    render(<MailList {...mailListProps('sent')} />);

    await user.click(screen.getByRole('checkbox', { name: 'Mara Alvarez: Cover final' }));
    expect(screen.getByRole('group', { name: '1 selected' })).toBeInTheDocument();

    // Delete only: no mark-read, spam or trash bulk actions on Sent.
    expect(screen.getByRole('button', { name: 'Delete' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Mark read' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Spam' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Trash' })).not.toBeInTheDocument();
  });

  it('keeps a delete button on the sent row itself', () => {
    render(<MailList {...mailListProps('sent')} />);
    expect(screen.getByRole('button', { name: 'Delete permanently' })).toBeInTheDocument();
  });

  it('keeps the full inbox row actions untouched', () => {
    render(<MailList {...mailListProps('inbox')} />);
    expect(screen.getByRole('button', { name: 'Mark as read' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Report spam' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Move to trash' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Delete permanently' })).toBeInTheDocument();
  });

  it('offers a two-step delete inside the sent reader', async () => {
    const user = userEvent.setup();
    const onDelete = vi.fn();
    render(
      <MailView
        mode="sent"
        message={{
          id: 'eml_row1',
          from_addr: 'you@pigeon.local',
          subject: 'Cover final',
          created_at: '2026-01-01T00:00:00Z',
        }}
        state="ready"
        demo={false}
        onBack={vi.fn()}
        onReply={vi.fn()}
        onForward={vi.fn()}
        onRetry={vi.fn()}
        onDelete={onDelete}
      />,
    );

    // Reply/forward stay hidden for sent mail.
    expect(screen.queryByRole('button', { name: 'Reply' })).not.toBeInTheDocument();

    // Permanent delete arms a confirmation first.
    await user.click(screen.getByRole('button', { name: 'Delete permanently' }));
    expect(onDelete).not.toHaveBeenCalled();
    await user.click(screen.getByRole('button', { name: 'Confirm' }));
    expect(onDelete).toHaveBeenCalledWith('eml_row1');
  });
});

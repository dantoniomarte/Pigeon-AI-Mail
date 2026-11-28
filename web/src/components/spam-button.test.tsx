import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';

import MailView from './MailView';
import type { MessageDetail } from '../api';

function baseMessage(): MessageDetail {
  return {
    id: 'msg-1',
    from_addr: 'sender@example.com',
    to: ['admin@example.com'],
    subject: 'Test subject',
    created_at: '2026-01-01T00:00:00Z',
    body_text: 'Body',
    body_html: '',
    read: true,
    attachments: [],
    auth: { spf: 'pass', dkim: 'pass', dmarc: 'pass' },
  } as unknown as MessageDetail;
}

function renderMailView(folder: 'inbox' | 'spam' | 'trash', onMove: ReturnType<typeof vi.fn>) {
  return render(
    <MailView
      mode="mail"
      folder={folder}
      message={baseMessage()}
      state="ready"
      demo={false}
      onBack={vi.fn()}
      onReply={vi.fn()}
      onForward={vi.fn()}
      onRetry={vi.fn()}
      onMove={onMove}
      onDelete={vi.fn()}
    />,
  );
}

describe('spam folder button (issue #134)', () => {
  it('shows "Not spam" and moves to inbox when the folder is spam', async () => {
    const onMove = vi.fn();
    renderMailView('spam', onMove);

    const button = screen.getByRole('button', { name: /not spam/i });
    expect(button).toBeTruthy();

    await userEvent.click(button);
    expect(onMove).toHaveBeenCalledWith('msg-1', 'inbox');
  });

  it('shows "Report spam" and moves to spam when the folder is inbox', async () => {
    const onMove = vi.fn();
    renderMailView('inbox', onMove);

    const button = screen.getByRole('button', { name: /report spam/i });
    expect(button).toBeTruthy();

    await userEvent.click(button);
    expect(onMove).toHaveBeenCalledWith('msg-1', 'spam');
  });
});

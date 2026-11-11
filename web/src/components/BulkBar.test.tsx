import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';

import BulkBar, { type BulkBarProps } from './BulkBar';

function setup(overrides: Partial<BulkBarProps> = {}): {
  props: BulkBarProps;
  rerenderWith: (next: Partial<BulkBarProps>) => void;
} {
  const props: BulkBarProps = {
    count: 3,
    busy: false,
    confirmDelete: false,
    canMarkRead: true,
    canSpam: true,
    canTrash: true,
    canDelete: true,
    canExport: true,
    onExport: vi.fn(),
    onMarkRead: vi.fn(),
    onMove: vi.fn(),
    onDelete: vi.fn(),
    onClear: vi.fn(),
    ...overrides,
  };
  const view = render(<BulkBar {...props} />);
  return {
    props,
    rerenderWith: (next) => view.rerender(<BulkBar {...props} {...next} />),
  };
}

describe('BulkBar', () => {
  it('announces how many rows are selected', () => {
    setup();
    expect(screen.getByRole('group', { name: '3 selected' })).toBeInTheDocument();
    expect(screen.getByText('3 selected')).toBeInTheDocument();
  });

  it('sends mark read and mark unread through one handler', async () => {
    const onMarkRead = vi.fn();
    setup({ onMarkRead });
    await userEvent.click(screen.getByRole('button', { name: 'Mark read' }));
    expect(onMarkRead).toHaveBeenCalledWith(true);
    await userEvent.click(screen.getByRole('button', { name: 'Mark unread' }));
    expect(onMarkRead).toHaveBeenCalledWith(false);
  });

  it('sends the target folder for spam and trash', async () => {
    const onMove = vi.fn();
    setup({ onMove });
    await userEvent.click(screen.getByRole('button', { name: 'Spam' }));
    expect(onMove).toHaveBeenCalledWith('spam');
    await userEvent.click(screen.getByRole('button', { name: 'Trash' }));
    expect(onMove).toHaveBeenCalledWith('trash');
  });

  it('pluralizes the armed delete confirmation', () => {
    const { rerenderWith } = setup();
    rerenderWith({ confirmDelete: true });
    expect(screen.getByRole('button', { name: 'Delete 3 messages permanently?' })).toBeInTheDocument();
  });

  it('uses the singular form for a single row', () => {
    const { rerenderWith } = setup();
    rerenderWith({ count: 1, confirmDelete: true });
    expect(screen.getByRole('button', { name: 'Delete 1 message permanently?' })).toBeInTheDocument();
  });

  it('disables every action while a bulk request is in flight', () => {
    setup({ busy: true });
    for (const button of screen.getAllByRole('button')) {
      expect(button).toBeDisabled();
    }
  });

  it('hides the actions the current folder cannot perform', () => {
    setup({ canSpam: false, canTrash: false, canDelete: false, canMarkRead: false });
    expect(screen.queryByRole('button', { name: 'Spam' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Delete' })).toBeNull();
    // Clearing the selection is always available.
    expect(screen.getByRole('button', { name: 'Clear selection' })).toBeInTheDocument();
  });
});

describe('BulkBar export', () => {
  it('offers the selection backup and forwards the click', async () => {
    const user = userEvent.setup();
    const onExport = vi.fn();
    setup({ onExport });
    await user.click(screen.getByRole('button', { name: 'Export selection (.mbox)' }));
    expect(onExport).toHaveBeenCalledTimes(1);
  });

  it('hides the export affordance when the capability is off', () => {
    setup({ canExport: false });
    expect(screen.queryByRole('button', { name: 'Export selection (.mbox)' })).not.toBeInTheDocument();
  });
});

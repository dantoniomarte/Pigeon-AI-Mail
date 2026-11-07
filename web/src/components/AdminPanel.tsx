import { useCallback, useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  AlertTriangle,
  AtSign,
  BellOff,
  BellRing,
  Building2,
  Check,
  Copy,
  Loader2,
  Lock,
  Pencil,
  Plus,
  RefreshCw,
  ShieldAlert,
  Trash2,
  UserMinus,
  UserPlus,
  Users,
  Waypoints,
  X,
} from 'lucide-react';

import {
  ApiError,
  assignAlias,
  assignCatchall,
  createAlias,
  createInvitation,
  createMember,
  createOrg,
  deleteAlias,
  deleteCatchall,
  deleteInvitation,
  fetchAliases,
  fetchCatchalls,
  fetchInvitations,
  fetchMyOrgs,
  fetchOrgMembers,
  patchCatchallAssignment,
  patchMember,
  setCatchall,
  unassignAlias,
  unassignCatchall,
  type AliasView,
  type CatchallAction,
  type CatchallRuleView,
  type InvitationView,
  type OrgMemberView,
  type OrgRole,
  type OrgView,
} from '../api';
import type { LoadState } from '../App';
import type { ToastKind } from './Toast';

export interface AdminPanelProps {
  apiKey: string | null;
  notify: (kind: ToastKind, message: string) => void;
}

/** A role an invitation or a fresh member may carry: `owner` is never granted here. */
type GrantableRole = Extract<OrgRole, 'admin' | 'member'>;

const GRANTABLE_ROLES: readonly GrantableRole[] = ['admin', 'member'];
const OWNER_ROLES: readonly OrgRole[] = ['owner', 'admin', 'member'];

const ROLE_BADGE: Record<OrgRole, string> = {
  owner: 'badge--role-owner',
  admin: 'badge--role-admin',
  member: 'badge--role-member',
};

const ROLE_LABEL: Record<OrgRole, string> = {
  owner: 'admin.roleOwner',
  admin: 'admin.roleAdmin',
  member: 'admin.roleMember',
};

/**
 * The organization console: members and roles, invitations, the one-time tokens
 * that get somebody in, and catch-all routing.
 *
 * Three answers the API can give shape the whole panel:
 *
 * * no organization — the account is a personal workspace and may create one;
 * * `role: member` — the endpoints answer `403`, so the panel says so instead of
 *   hiding the entry (an owner should be able to find the feature by name);
 * * `409 last-owner` — the last owner row keeps its role control disabled.
 *
 * Message bodies never appear here: this panel administers who belongs to the
 * organization and where its mail is delivered, not what anybody wrote.
 */
export default function AdminPanel({ apiKey, notify }: AdminPanelProps): JSX.Element {
  const { t, i18n } = useTranslation();

  const [orgs, setOrgs] = useState<OrgView[]>([]);
  const [orgsState, setOrgsState] = useState<LoadState>('idle');
  const [orgsToken, setOrgsToken] = useState(0);

  const org = orgs[0] ?? null;
  const orgId = org?.id ?? null;
  // A personal workspace belongs to no organization and is its own owner, which
  // is exactly what the catch-all endpoints accept.
  const callerRole: OrgRole = org?.role ?? 'owner';
  const isOrgAdmin = callerRole === 'owner' || callerRole === 'admin';

  const [members, setMembers] = useState<OrgMemberView[]>([]);
  const [membersState, setMembersState] = useState<LoadState>('idle');
  const [membersToken, setMembersToken] = useState(0);

  const [invitations, setInvitations] = useState<InvitationView[]>([]);
  const [invitesState, setInvitesState] = useState<LoadState>('idle');
  const [invitesToken, setInvitesToken] = useState(0);

  const [rules, setRules] = useState<CatchallRuleView[]>([]);
  const [rulesState, setRulesState] = useState<LoadState>('idle');
  const [rulesToken, setRulesToken] = useState(0);
  /** Which mailbox the admin picked to add to a rule, keyed by domain. */
  const [ruleAssignee, setRuleAssignee] = useState<Record<string, string>>({});

  const [aliases, setAliases] = useState<AliasView[]>([]);
  const [aliasesState, setAliasesState] = useState<LoadState>('idle');
  const [aliasesToken, setAliasesToken] = useState(0);
  const [newAlias, setNewAlias] = useState('');
  const [creatingAlias, setCreatingAlias] = useState(false);
  const [aliasError, setAliasError] = useState<string | null>(null);
  const [pendingAlias, setPendingAlias] = useState<number | null>(null);
  const [busyAlias, setBusyAlias] = useState<number | null>(null);
  /** Which mailbox the admin picked to add to an alias, keyed by alias id. */
  const [aliasAssignee, setAliasAssignee] = useState<Record<number, string>>({});
  /** One in-flight assignee mutation at a time, keyed `domain:account` / `alias:account`. */
  const [busyAssignee, setBusyAssignee] = useState<string | null>(null);

  /* Create organization. */
  const [newOrgName, setNewOrgName] = useState('');
  const [creatingOrg, setCreatingOrg] = useState(false);
  const [orgError, setOrgError] = useState<string | null>(null);

  /* Invite by email. */
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteRole, setInviteRole] = useState<GrantableRole>('member');
  const [inviting, setInviting] = useState(false);
  const [inviteError, setInviteError] = useState<string | null>(null);
  // The token exists only in the creation response: it is shown once and the
  // invitation list will never carry it again.
  const [inviteToken, setInviteToken] = useState<string | null>(null);

  /* Create a member account directly. */
  const [memberEmail, setMemberEmail] = useState('');
  const [memberName, setMemberName] = useState('');
  const [memberRole, setMemberRole] = useState<GrantableRole>('member');
  const [creatingMember, setCreatingMember] = useState(false);
  const [memberError, setMemberError] = useState<string | null>(null);
  const [bootstrapToken, setBootstrapToken] = useState<string | null>(null);

  /* Per-row state. */
  const [busyMember, setBusyMember] = useState<number | null>(null);
  const [renamingId, setRenamingId] = useState<number | null>(null);
  const [renameValue, setRenameValue] = useState('');
  const [pendingInvite, setPendingInvite] = useState<number | null>(null);
  const [busyInvite, setBusyInvite] = useState<number | null>(null);

  /* Catch-all form. */
  const [ruleDomain, setRuleDomain] = useState('');
  const [ruleAction, setRuleAction] = useState<CatchallAction>('route');
  const [ruleTarget, setRuleTarget] = useState('');
  const [savingRule, setSavingRule] = useState(false);
  const [ruleError, setRuleError] = useState<string | null>(null);
  const [pendingRule, setPendingRule] = useState<string | null>(null);
  const [busyRule, setBusyRule] = useState<string | null>(null);

  const canAdminister = orgsState === 'ready' && isOrgAdmin;

  useEffect(() => {
    let cancelled = false;
    setOrgsState('loading');
    void fetchMyOrgs(apiKey)
      .then((list) => {
        if (cancelled) {
          return;
        }
        setOrgs(list);
        setOrgsState('ready');
      })
      .catch((error: unknown) => {
        if (cancelled) {
          return;
        }
        setOrgsState(error instanceof ApiError && error.isForbidden ? 'forbidden' : 'error');
      });
    return () => {
      cancelled = true;
    };
  }, [apiKey, orgsToken]);

  useEffect(() => {
    if (orgId === null || !isOrgAdmin) {
      setMembers([]);
      setMembersState(orgId === null ? 'idle' : 'forbidden');
      return;
    }
    let cancelled = false;
    setMembersState('loading');
    void fetchOrgMembers(apiKey, orgId)
      .then((list) => {
        if (cancelled) {
          return;
        }
        setMembers(list);
        setMembersState('ready');
      })
      .catch((error: unknown) => {
        if (cancelled) {
          return;
        }
        setMembersState(error instanceof ApiError && error.isForbidden ? 'forbidden' : 'error');
      });
    return () => {
      cancelled = true;
    };
  }, [apiKey, orgId, isOrgAdmin, membersToken]);

  useEffect(() => {
    if (orgId === null || !isOrgAdmin) {
      setInvitations([]);
      setInvitesState('idle');
      return;
    }
    let cancelled = false;
    setInvitesState('loading');
    void fetchInvitations(apiKey, orgId)
      .then((list) => {
        if (cancelled) {
          return;
        }
        setInvitations(list);
        setInvitesState('ready');
      })
      .catch((error: unknown) => {
        if (cancelled) {
          return;
        }
        setInvitesState(error instanceof ApiError && error.isForbidden ? 'forbidden' : 'error');
      });
    return () => {
      cancelled = true;
    };
  }, [apiKey, orgId, isOrgAdmin, invitesToken]);

  useEffect(() => {
    if (!canAdminister) {
      setRules([]);
      setRulesState('idle');
      return;
    }
    let cancelled = false;
    setRulesState('loading');
    void fetchCatchalls(apiKey)
      .then((list) => {
        if (cancelled) {
          return;
        }
        setRules(list);
        setRulesState('ready');
      })
      .catch((error: unknown) => {
        if (cancelled) {
          return;
        }
        setRulesState(error instanceof ApiError && error.isForbidden ? 'forbidden' : 'error');
      });
    return () => {
      cancelled = true;
    };
  }, [apiKey, canAdminister, rulesToken]);

  useEffect(() => {
    if (!canAdminister) {
      setAliases([]);
      setAliasesState('idle');
      return;
    }
    let cancelled = false;
    setAliasesState('loading');
    void fetchAliases(apiKey)
      .then((list) => {
        if (cancelled) {
          return;
        }
        setAliases(list);
        setAliasesState('ready');
      })
      .catch((error: unknown) => {
        if (cancelled) {
          return;
        }
        setAliasesState(error instanceof ApiError && error.isForbidden ? 'forbidden' : 'error');
      });
    return () => {
      cancelled = true;
    };
  }, [aliasesToken, apiKey, canAdminister]);

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

  const copy = useCallback(
    (text: string) => {
      if (navigator.clipboard === undefined) {
        notify('error', t('common.error'));
        return;
      }
      void navigator.clipboard
        .writeText(text)
        .then(() => notify('success', t('toast.copied')))
        .catch(() => notify('error', t('common.error')));
    },
    [notify, t],
  );

  const refreshMembers = useCallback(() => setMembersToken((token) => token + 1), []);
  const refreshInvites = useCallback(() => setInvitesToken((token) => token + 1), []);

  /* ------------------------------------------------------------ create org */

  const submitOrg = useCallback(
    (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      const name = newOrgName.trim();
      if (name.length === 0 || creatingOrg) {
        return;
      }
      setCreatingOrg(true);
      setOrgError(null);
      void createOrg(apiKey, name)
        .then(() => {
          setNewOrgName('');
          setOrgsToken((token) => token + 1);
          notify('success', t('admin.orgCreated'));
        })
        .catch(() => setOrgError(t('common.error')))
        .finally(() => setCreatingOrg(false));
    },
    [apiKey, creatingOrg, newOrgName, notify, t],
  );

  /* ------------------------------------------------------------- invite */

  const submitInvite = useCallback(
    (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      const email = inviteEmail.trim();
      if (orgId === null || email.length === 0 || inviting) {
        return;
      }
      setInviting(true);
      setInviteError(null);
      void createInvitation(apiKey, orgId, email, inviteRole)
        .then((created) => {
          setInviteToken(created.token);
          setInviteEmail('');
          refreshInvites();
          notify('success', t('admin.inviteSent'));
        })
        .catch(() => setInviteError(t('common.error')))
        .finally(() => setInviting(false));
    },
    [apiKey, inviteEmail, inviteRole, inviting, notify, orgId, refreshInvites, t],
  );

  /* ------------------------------------------------------ create member */

  const submitMember = useCallback(
    (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      const email = memberEmail.trim();
      if (orgId === null || email.length === 0 || creatingMember) {
        return;
      }
      setCreatingMember(true);
      setMemberError(null);
      void createMember(apiKey, orgId, email, memberName, memberRole)
        .then((created) => {
          setBootstrapToken(created.bootstrap_token);
          setMemberEmail('');
          setMemberName('');
          refreshMembers();
          // Creating a member also mints the bootstrap invitation row, so the
          // pending list has to be re-read or it would look out of date.
          refreshInvites();
          notify('success', t('admin.memberCreated'));
        })
        .catch(() => setMemberError(t('common.error')))
        .finally(() => setCreatingMember(false));
    },
    [
      apiKey,
      creatingMember,
      memberEmail,
      memberName,
      memberRole,
      notify,
      orgId,
      refreshInvites,
      refreshMembers,
      t,
    ],
  );

  /* --------------------------------------------------------- member rows */

  const ownerCount = useMemo(
    () => members.filter((member) => member.role === 'owner').length,
    [members],
  );
  const lastOwner = ownerCount <= 1;

  /** Owners are the only ones who may move the `owner` role; admins see a badge. */
  const canEditRole = useCallback(
    (member: OrgMemberView): boolean => callerRole === 'owner' || member.role !== 'owner',
    [callerRole],
  );

  const changeRole = useCallback(
    (member: OrgMemberView, role: OrgRole) => {
      if (orgId === null || role === member.role || busyMember !== null) {
        return;
      }
      setBusyMember(member.account_id);
      void patchMember(apiKey, orgId, member.account_id, { role })
        .then(() => {
          refreshMembers();
          notify('success', t('admin.memberUpdated'));
        })
        .catch((error: unknown) => {
          // The one conflict the API documents here is demoting the last owner.
          notify(
            'error',
            error instanceof ApiError && error.status === 409
              ? t('admin.lastOwner')
              : t('common.error'),
          );
        })
        .finally(() => setBusyMember(null));
    },
    [apiKey, busyMember, notify, orgId, refreshMembers, t],
  );

  const startRename = useCallback((member: OrgMemberView) => {
    setRenamingId(member.account_id);
    setRenameValue(member.display_name);
  }, []);

  const cancelRename = useCallback(() => {
    setRenamingId(null);
    setRenameValue('');
  }, []);

  const saveRename = useCallback(
    (member: OrgMemberView) => {
      const name = renameValue.trim();
      if (orgId === null || name.length === 0 || busyMember !== null) {
        return;
      }
      setBusyMember(member.account_id);
      void patchMember(apiKey, orgId, member.account_id, { display_name: name })
        .then(() => {
          setRenamingId(null);
          setRenameValue('');
          refreshMembers();
          notify('success', t('admin.memberUpdated'));
        })
        .catch(() => notify('error', t('common.error')))
        .finally(() => setBusyMember(null));
    },
    [apiKey, busyMember, notify, orgId, refreshMembers, renameValue, t],
  );

  /* ---------------------------------------------------- pending invites */

  const pendingInvites = useMemo(() => {
    const now = Date.now();
    return invitations.filter((invitation) => {
      if (invitation.accepted_at !== undefined) {
        return false;
      }
      const expires = Date.parse(invitation.expires_at);
      return Number.isNaN(expires) || expires > now;
    });
  }, [invitations]);

  const removeInvitation = useCallback(
    (invitation: InvitationView) => {
      if (orgId === null) {
        return;
      }
      if (pendingInvite !== invitation.id) {
        setPendingInvite(invitation.id);
        return;
      }
      setBusyInvite(invitation.id);
      void deleteInvitation(apiKey, orgId, invitation.id)
        .then(() => {
          setInvitations((current) => current.filter((row) => row.id !== invitation.id));
          notify('success', t('admin.inviteRevoked'));
        })
        .catch(() => notify('error', t('common.error')))
        .finally(() => {
          setBusyInvite(null);
          setPendingInvite(null);
        });
    },
    [apiKey, notify, orgId, pendingInvite, t],
  );

  /* ------------------------------------------------------------ catch-all */

  const emailOf = useMemo(() => {
    const map = new Map<number, string>();
    for (const member of members) {
      map.set(member.account_id, member.email);
    }
    return map;
  }, [members]);

  /**
   * Route targets are mailboxes of the very domain being configured — the API
   * refuses anything else — so the picker only ever offers those.
   */
  const ruleTargets = useMemo(() => {
    const domain = ruleDomain.trim().toLowerCase();
    if (domain.length === 0) {
      return [];
    }
    return members.filter((member) => member.email.toLowerCase().endsWith(`@${domain}`));
  }, [members, ruleDomain]);

  const submitRule = useCallback(
    (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      const domain = ruleDomain.trim().toLowerCase();
      if (domain.length === 0 || savingRule) {
        return;
      }
      const targetAccountId = Number.parseInt(ruleTarget, 10);
      if (ruleAction === 'route' && !Number.isFinite(targetAccountId)) {
        setRuleError(t('admin.catchallTarget'));
        return;
      }
      setSavingRule(true);
      setRuleError(null);
      // Two calls, on purpose: the rule is the domain decision, the mailbox is an
      // assignment. Flipping the action later therefore never forgets who was
      // receiving the mail.
      void setCatchall(apiKey, domain, ruleAction)
        .then(() => {
          if (ruleAction !== 'route' || !Number.isFinite(targetAccountId)) {
            return undefined;
          }
          return assignCatchall(apiKey, domain, targetAccountId).catch(() => undefined);
        })
        .then(() => {
          setRuleDomain('');
          setRuleTarget('');
          setRulesToken((token) => token + 1);
          notify('success', t('admin.catchallAdded'));
        })
        .catch(() => setRuleError(t('common.error')))
        .finally(() => setSavingRule(false));
    },
    [apiKey, notify, ruleAction, ruleDomain, ruleTarget, savingRule, t],
  );

  const removeRule = useCallback(
    (rule: CatchallRuleView) => {
      if (pendingRule !== rule.domain) {
        setPendingRule(rule.domain);
        return;
      }
      setBusyRule(rule.domain);
      void deleteCatchall(apiKey, rule.domain)
        .then(() => {
          setRules((current) => current.filter((row) => row.domain !== rule.domain));
          notify('success', t('admin.catchallDeleted'));
        })
        .catch(() => notify('error', t('common.error')))
        .finally(() => {
          setBusyRule(null);
          setPendingRule(null);
        });
    },
    [apiKey, notify, pendingRule, t],
  );

  const addCatchallAssignee = useCallback(
    (domain: string) => {
      const raw = ruleAssignee[domain] ?? '';
      const accountId = Number.parseInt(raw, 10);
      if (!Number.isFinite(accountId)) {
        return;
      }
      const key = `${domain}:${accountId}`;
      setBusyAssignee(key);
      void assignCatchall(apiKey, domain, accountId)
        .then((rule) => {
          setRules((current) => current.map((row) => (row.domain === rule.domain ? rule : row)));
          setRuleAssignee((current) => ({ ...current, [domain]: '' }));
          notify('success', t('admin.catchallAssigneeAdded'));
        })
        .catch(() => notify('error', t('common.error')))
        .finally(() => setBusyAssignee(null));
    },
    [apiKey, notify, ruleAssignee, t],
  );

  const dropCatchallAssignee = useCallback(
    (domain: string, accountId: number) => {
      const key = `${domain}:${accountId}`;
      setBusyAssignee(key);
      void unassignCatchall(apiKey, domain, accountId)
        .then(() => {
          setRules((current) =>
            current.map((row) =>
              row.domain === domain
                ? {
                    ...row,
                    assignments: (row.assignments ?? []).filter(
                      (assignment) => assignment.account_id !== accountId,
                    ),
                  }
                : row,
            ),
          );
          notify('success', t('admin.catchallAssigneeRemoved'));
        })
        .catch(() => notify('error', t('common.error')))
        .finally(() => setBusyAssignee(null));
    },
    [apiKey, notify, t],
  );

  const forceCatchall = useCallback(
    (domain: string, accountId: number, paused: boolean) => {
      const key = `${domain}:${accountId}`;
      setBusyAssignee(key);
      void patchCatchallAssignment(apiKey, domain, accountId, paused)
        .then(() => {
          setRules((current) =>
            current.map((row) =>
              row.domain === domain
                ? {
                    ...row,
                    assignments: (row.assignments ?? []).map((assignment) =>
                      assignment.account_id === accountId
                        ? { ...assignment, paused }
                        : assignment,
                    ),
                  }
                : row,
            ),
          );
          notify('success', t('admin.catchallForced'));
        })
        .catch(() => notify('error', t('common.error')))
        .finally(() => setBusyAssignee(null));
    },
    [apiKey, notify, t],
  );

  /* ------------------------------------------------------------- aliases */

  const submitAlias = useCallback(
    (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      const address = newAlias.trim();
      if (address.length === 0 || creatingAlias) {
        return;
      }
      setCreatingAlias(true);
      setAliasError(null);
      void createAlias(apiKey, address)
        .then(() => {
          setNewAlias('');
          setAliasesToken((token) => token + 1);
          notify('success', t('admin.aliasCreated'));
        })
        .catch(() => setAliasError(t('common.error')))
        .finally(() => setCreatingAlias(false));
    },
    [apiKey, creatingAlias, newAlias, notify, t],
  );

  const removeAlias = useCallback(
    (alias: AliasView) => {
      if (pendingAlias !== alias.id) {
        setPendingAlias(alias.id);
        return;
      }
      setBusyAlias(alias.id);
      void deleteAlias(apiKey, alias.id)
        .then(() => {
          setAliases((current) => current.filter((row) => row.id !== alias.id));
          notify('success', t('admin.aliasDeleted'));
        })
        .catch(() => notify('error', t('common.error')))
        .finally(() => {
          setBusyAlias(null);
          setPendingAlias(null);
        });
    },
    [apiKey, notify, pendingAlias, t],
  );

  const addAliasAssignee = useCallback(
    (alias: AliasView) => {
      const raw = aliasAssignee[alias.id] ?? '';
      const accountId = Number.parseInt(raw, 10);
      if (!Number.isFinite(accountId)) {
        return;
      }
      const key = `alias:${alias.id}:${accountId}`;
      setBusyAssignee(key);
      void assignAlias(apiKey, alias.id, accountId)
        .then((updated) => {
          setAliases((current) => current.map((row) => (row.id === updated.id ? updated : row)));
          setAliasAssignee((current) => ({ ...current, [alias.id]: '' }));
          notify('success', t('admin.aliasAssigned'));
        })
        .catch(() => notify('error', t('common.error')))
        .finally(() => setBusyAssignee(null));
    },
    [aliasAssignee, apiKey, notify, t],
  );

  const dropAliasAssignee = useCallback(
    (alias: AliasView, accountId: number) => {
      const key = `alias:${alias.id}:${accountId}`;
      setBusyAssignee(key);
      void unassignAlias(apiKey, alias.id, accountId)
        .then((updated) => {
          setAliases((current) => current.map((row) => (row.id === updated.id ? updated : row)));
          notify('success', t('admin.aliasUnassigned'));
        })
        .catch(() => notify('error', t('common.error')))
        .finally(() => setBusyAssignee(null));
    },
    [apiKey, notify, t],
  );

  /* -------------------------------------------------------------- pieces */

  const loadingBlock = (
    <div className="stack" aria-busy="true" aria-label={t('common.loading')}>
      <span className="skeleton skeleton--line" />
      <span className="skeleton skeleton--line skeleton--short" />
    </div>
  );

  const errorBlock = (retry: () => void): JSX.Element => (
    <div className="state-card state-card--compact" role="alert">
      <span className="state-card__icon">
        <AlertTriangle size={20} />
      </span>
      <h3>{t('common.error')}</h3>
      <button type="button" className="btn btn--ghost" onClick={retry}>
        <RefreshCw size={15} aria-hidden="true" />
        {t('common.retry')}
      </button>
    </div>
  );

  const memberRows = members.map((member) => {
    const busy = busyMember === member.account_id;
    const lockedByLastOwner = member.role === 'owner' && lastOwner;
    const roleChoices = callerRole === 'owner' ? OWNER_ROLES : GRANTABLE_ROLES;
    const renaming = renamingId === member.account_id;

    return (
      <tr key={member.account_id}>
        <td className="admin-table__email">{member.email}</td>
        <td>
          {renaming ? (
            <span className="admin-table__inline">
              <input
                className="input input--small admin-table__name-input"
                value={renameValue}
                aria-label={t('admin.memberName')}
                onChange={(event) => setRenameValue(event.target.value)}
              />
              <button
                type="button"
                className="icon-btn"
                onClick={() => saveRename(member)}
                disabled={busy || renameValue.trim().length === 0}
                aria-label={t('admin.save')}
                title={t('admin.save')}
              >
                {busy ? <Loader2 size={15} className="spin" aria-hidden="true" /> : <Check size={15} />}
              </button>
              <button
                type="button"
                className="icon-btn"
                onClick={cancelRename}
                aria-label={t('common.cancel')}
                title={t('common.cancel')}
              >
                <X size={15} />
              </button>
            </span>
          ) : (
            <span className="admin-table__inline">
              <span>{member.display_name.length > 0 ? member.display_name : '—'}</span>
              <button
                type="button"
                className="icon-btn admin-table__edit"
                onClick={() => startRename(member)}
                disabled={busy}
                aria-label={`${t('admin.rename')} — ${member.email}`}
                title={t('admin.rename')}
              >
                <Pencil size={14} />
              </button>
            </span>
          )}
        </td>
        <td>
          {canEditRole(member) ? (
            <select
              className="input input--small admin-table__select"
              value={member.role}
              aria-label={`${t('admin.memberRole')} — ${member.email}`}
              disabled={busy || lockedByLastOwner}
              title={lockedByLastOwner ? t('admin.lastOwner') : undefined}
              onChange={(event) => changeRole(member, event.target.value as OrgRole)}
            >
              {roleChoices.map((role) => (
                <option key={role} value={role}>
                  {t(ROLE_LABEL[role])}
                </option>
              ))}
            </select>
          ) : (
            <span className={`badge ${ROLE_BADGE[member.role]}`}>{t(ROLE_LABEL[member.role])}</span>
          )}
        </td>
        <td>
          {member.status !== undefined ? (
            <span className="badge badge--muted">{member.status}</span>
          ) : (
            <span className="admin-table__meta">{formatDate(member.created_at)}</span>
          )}
        </td>
      </tr>
    );
  });

  return (
    <section className="admin" aria-label={t('admin.title')}>
      <header className="admin__head">
        <h1 className="admin__title">{t('admin.title')}</h1>
        <p className="admin__subtitle">{t('admin.subtitle')}</p>
      </header>

      <div className="admin__body">
        <div className="admin__privacy" role="note">
          <Lock size={16} aria-hidden="true" />
          <p>{t('admin.privacyNote')}</p>
        </div>

        {orgsState === 'loading' || orgsState === 'idle' ? loadingBlock : null}

        {orgsState === 'error' || orgsState === 'forbidden'
          ? errorBlock(() => setOrgsToken((token) => token + 1))
          : null}

        {orgsState === 'ready' && !isOrgAdmin ? (
          <>
            <div className="state-card state-card--compact" role="status">
              <span className="state-card__icon state-card__icon--warn">
                <ShieldAlert size={20} />
              </span>
              <h3>{t('admin.notAdmin')}</h3>
              <p>{t('admin.notAdminBody')}</p>
            </div>
            {org !== null ? (
              <section className="panel">
                <div className="panel__head">
                  <h2>
                    <Building2 size={15} aria-hidden="true" />
                    {org.name}
                  </h2>
                  <p>{t('admin.members')}</p>
                </div>
                <div className="admin__orgmeta">
                  <span className={`badge ${ROLE_BADGE[callerRole]}`}>
                    {t(ROLE_LABEL[callerRole])}
                  </span>
                  <span className="admin-table__meta">{formatDate(org.created_at)}</span>
                </div>
              </section>
            ) : null}
          </>
        ) : null}

        {orgsState === 'ready' && isOrgAdmin && org === null ? (
          <section className="panel">
            <div className="panel__head">
              <h2>
                <Building2 size={15} aria-hidden="true" />
                {t('admin.noOrg')}
              </h2>
              <p>{t('admin.noOrgBody')}</p>
            </div>
            <form className="settings__form" onSubmit={submitOrg}>
              <label className="field field--plain">
                <span className="field__label">{t('admin.orgName')}</span>
                <input
                  className="input"
                  type="text"
                  value={newOrgName}
                  maxLength={100}
                  placeholder={t('admin.orgName')}
                  onChange={(event) => setNewOrgName(event.target.value)}
                />
              </label>
              {orgError !== null ? (
                <p className="field__error" role="alert">
                  {orgError}
                </p>
              ) : null}
              <button
                type="submit"
                className="btn btn--primary"
                disabled={creatingOrg || newOrgName.trim().length === 0}
              >
                {creatingOrg ? (
                  <Loader2 size={15} className="spin" aria-hidden="true" />
                ) : (
                  <Plus size={15} aria-hidden="true" />
                )}
                {t('admin.createOrg')}
              </button>
            </form>
          </section>
        ) : null}

        {orgsState === 'ready' && isOrgAdmin && org !== null ? (
          <>
            <div className="admin__grid">
              <section className="panel">
                <div className="panel__head">
                  <h2>
                    <Users size={15} aria-hidden="true" />
                    {org.name}
                    <span className={`badge ${ROLE_BADGE[callerRole]}`}>
                      {t(ROLE_LABEL[callerRole])}
                    </span>
                  </h2>
                  <p>{t('admin.members')}</p>
                </div>

                {membersState === 'loading' || membersState === 'idle' ? loadingBlock : null}
                {membersState === 'error' || membersState === 'forbidden'
                  ? errorBlock(() => setMembersToken((token) => token + 1))
                  : null}

                {membersState === 'ready' ? (
                  <div className="admin-table__wrap">
                    <table className="admin-table">
                      <thead>
                        <tr>
                          <th scope="col">{t('admin.memberEmail')}</th>
                          <th scope="col">{t('admin.memberName')}</th>
                          <th scope="col">{t('admin.memberRole')}</th>
                          {/* Row-level controls carry their own accessible names. */}
                          <th scope="col" />
                        </tr>
                      </thead>
                      <tbody>{memberRows}</tbody>
                    </table>
                  </div>
                ) : null}

                {membersState === 'ready' && lastOwner ? (
                  <p className="admin__hint" role="note">
                    <ShieldAlert size={13} aria-hidden="true" />
                    {t('admin.lastOwner')}
                  </p>
                ) : null}
              </section>

              <div className="admin__forms">
                <section className="panel">
                  <div className="panel__head">
                    <h2>
                      <UserPlus size={15} aria-hidden="true" />
                      {t('admin.invite')}
                    </h2>
                    <p>{t('admin.inviteTokenOnce')}</p>
                  </div>
                  {inviteToken !== null ? (
                    <div className="secret-reveal" role="status">
                      <div className="secret-reveal__head">
                        <Lock size={14} aria-hidden="true" />
                        <span>{t('admin.inviteTokenOnce')}</span>
                      </div>
                      <div className="secret-reveal__value">
                        <code>{inviteToken}</code>
                        <button
                          type="button"
                          className="btn btn--quiet btn--small"
                          onClick={() => copy(inviteToken)}
                        >
                          <Copy size={14} aria-hidden="true" />
                          {t('common.copy')}
                        </button>
                      </div>
                    </div>
                  ) : null}
                  <form className="settings__form" onSubmit={submitInvite}>
                    <label className="field field--plain">
                      <span className="field__label">{t('admin.inviteEmail')}</span>
                      <input
                        className="input"
                        type="email"
                        inputMode="email"
                        autoComplete="off"
                        value={inviteEmail}
                        placeholder={t('login.emailPlaceholder')}
                        onChange={(event) => setInviteEmail(event.target.value)}
                      />
                    </label>
                    <label className="field field--plain">
                      <span className="field__label">{t('admin.inviteRole')}</span>
                      <select
                        className="input"
                        value={inviteRole}
                        onChange={(event) => setInviteRole(event.target.value as GrantableRole)}
                      >
                        {GRANTABLE_ROLES.map((role) => (
                          <option key={role} value={role}>
                            {t(ROLE_LABEL[role])}
                          </option>
                        ))}
                      </select>
                    </label>
                    {inviteError !== null ? (
                      <p className="field__error" role="alert">
                        {inviteError}
                      </p>
                    ) : null}
                    <button
                      type="submit"
                      className="btn btn--primary"
                      disabled={inviting || inviteEmail.trim().length === 0}
                    >
                      {inviting ? (
                        <Loader2 size={15} className="spin" aria-hidden="true" />
                      ) : (
                        <Plus size={15} aria-hidden="true" />
                      )}
                      {t('admin.invite')}
                    </button>
                  </form>
                </section>

                <section className="panel">
                  <div className="panel__head">
                    <h2>
                      <Plus size={15} aria-hidden="true" />
                      {t('admin.createMember')}
                    </h2>
                    <p>{t('admin.bootstrapTokenOnce')}</p>
                  </div>
                  {bootstrapToken !== null ? (
                    <div className="secret-reveal" role="status">
                      <div className="secret-reveal__head">
                        <Lock size={14} aria-hidden="true" />
                        <span>{t('admin.bootstrapTokenOnce')}</span>
                      </div>
                      <div className="secret-reveal__value">
                        <code>{bootstrapToken}</code>
                        <button
                          type="button"
                          className="btn btn--quiet btn--small"
                          onClick={() => copy(bootstrapToken)}
                        >
                          <Copy size={14} aria-hidden="true" />
                          {t('common.copy')}
                        </button>
                      </div>
                    </div>
                  ) : null}
                  <form className="settings__form" onSubmit={submitMember}>
                    <label className="field field--plain">
                      <span className="field__label">{t('admin.memberEmail')}</span>
                      <input
                        className="input"
                        type="email"
                        inputMode="email"
                        autoComplete="off"
                        value={memberEmail}
                        placeholder={t('login.emailPlaceholder')}
                        onChange={(event) => setMemberEmail(event.target.value)}
                      />
                    </label>
                    <label className="field field--plain">
                      <span className="field__label">{t('admin.memberName')}</span>
                      <input
                        className="input"
                        type="text"
                        value={memberName}
                        maxLength={100}
                        onChange={(event) => setMemberName(event.target.value)}
                      />
                    </label>
                    <label className="field field--plain">
                      <span className="field__label">{t('admin.memberRole')}</span>
                      <select
                        className="input"
                        value={memberRole}
                        onChange={(event) => setMemberRole(event.target.value as GrantableRole)}
                      >
                        {GRANTABLE_ROLES.map((role) => (
                          <option key={role} value={role}>
                            {t(ROLE_LABEL[role])}
                          </option>
                        ))}
                      </select>
                    </label>
                    {memberError !== null ? (
                      <p className="field__error" role="alert">
                        {memberError}
                      </p>
                    ) : null}
                    <button
                      type="submit"
                      className="btn btn--primary"
                      disabled={creatingMember || memberEmail.trim().length === 0}
                    >
                      {creatingMember ? (
                        <Loader2 size={15} className="spin" aria-hidden="true" />
                      ) : (
                        <Plus size={15} aria-hidden="true" />
                      )}
                      {t('admin.createMember')}
                    </button>
                  </form>
                </section>
              </div>
            </div>

            {invitesState === 'ready' && pendingInvites.length > 0 ? (
              <section className="panel">
                <div className="panel__head">
                  <h2>{t('admin.pendingInvites')}</h2>
                </div>
                <div className="admin-table__wrap">
                  <table className="admin-table">
                    <thead>
                      <tr>
                        <th scope="col">{t('admin.memberEmail')}</th>
                        <th scope="col">{t('admin.inviteRole')}</th>
                        <th scope="col" />
                      </tr>
                    </thead>
                    <tbody>
                      {pendingInvites.map((invitation) => (
                        <tr key={invitation.id}>
                          <td>
                            <div className="admin-table__email">{invitation.email}</div>
                            <div className="admin-table__meta">
                              {formatDate(invitation.expires_at)}
                            </div>
                          </td>
                          <td>
                            <span className={`badge ${ROLE_BADGE[invitation.role]}`}>
                              {t(ROLE_LABEL[invitation.role])}
                            </span>
                          </td>
                          <td>
                            <div className="admin-table__actions">
                              <button
                                type="button"
                                className={`btn btn--small ${
                                  pendingInvite === invitation.id ? 'btn--danger' : 'btn--ghost'
                                }`}
                                onClick={() => removeInvitation(invitation)}
                                disabled={busyInvite === invitation.id}
                              >
                                {busyInvite === invitation.id ? (
                                  <Loader2 size={14} className="spin" aria-hidden="true" />
                                ) : (
                                  <Trash2 size={14} aria-hidden="true" />
                                )}
                                {pendingInvite === invitation.id
                                  ? `${t('common.delete')}?`
                                  : t('common.delete')}
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>
            ) : null}
          </>
        ) : null}

        {canAdminister ? (
          <section className="panel">
            <div className="panel__head">
              <h2>
                <Waypoints size={15} aria-hidden="true" />
                {t('admin.catchallTitle')}
              </h2>
              <p>{t('admin.catchallBody')}</p>
            </div>

            {rulesState === 'loading' || rulesState === 'idle' ? loadingBlock : null}
            {rulesState === 'error' || rulesState === 'forbidden'
              ? errorBlock(() => setRulesToken((token) => token + 1))
              : null}

            {rulesState === 'ready' && rules.length > 0 ? (
              <div className="admin-table__wrap">
                <table className="admin-table">
                  <thead>
                    <tr>
                      <th scope="col">{t('admin.catchallDomain')}</th>
                      <th scope="col">{t('admin.catchallAction')}</th>
                      <th scope="col">{t('admin.catchallAssignees')}</th>
                      <th scope="col" />
                    </tr>
                  </thead>
                  <tbody>
                    {rules.map((rule) => (
                      <tr key={rule.domain}>
                        <td className="admin-table__email mono">{rule.domain}</td>
                        <td>
                          <span
                            className={`badge ${
                              rule.action === 'route' ? 'badge--enc' : 'badge--muted'
                            }`}
                          >
                            {rule.action === 'route'
                              ? t('admin.actionRoute')
                              : t('admin.actionDiscard')}
                          </span>
                        </td>
                        <td className="admin-table__meta">
                          {(rule.assignments ?? []).length === 0 ? (
                            <span className="admin__hint">{t('admin.catchallNoAssignees')}</span>
                          ) : (
                            <ul className="tag-list">
                              {(rule.assignments ?? []).map((assignment) => {
                                const key = `${rule.domain}:${assignment.account_id}`;
                                return (
                                  <li
                                    key={assignment.account_id}
                                    className={`badge ${
                                      assignment.paused ? 'badge--muted' : 'badge--enc'
                                    }`}
                                  >
                                    {assignment.email ??
                                      emailOf.get(assignment.account_id) ??
                                      `#${assignment.account_id}`}
                                    <button
                                      type="button"
                                      className="icon-btn icon-btn--tiny"
                                      onClick={() =>
                                        forceCatchall(
                                          rule.domain,
                                          assignment.account_id,
                                          !assignment.paused,
                                        )
                                      }
                                      disabled={busyAssignee === key}
                                      aria-label={
                                        assignment.paused
                                          ? t('admin.catchallResume')
                                          : t('admin.catchallPause')
                                      }
                                      title={
                                        assignment.paused
                                          ? t('admin.catchallResume')
                                          : t('admin.catchallPause')
                                      }
                                    >
                                      {assignment.paused ? (
                                        <BellRing size={12} aria-hidden="true" />
                                      ) : (
                                        <BellOff size={12} aria-hidden="true" />
                                      )}
                                    </button>
                                    <button
                                      type="button"
                                      className="icon-btn icon-btn--tiny"
                                      onClick={() =>
                                        dropCatchallAssignee(rule.domain, assignment.account_id)
                                      }
                                      disabled={busyAssignee === key}
                                      aria-label={t('admin.catchallUnassign')}
                                      title={t('admin.catchallUnassign')}
                                    >
                                      <UserMinus size={12} aria-hidden="true" />
                                    </button>
                                  </li>
                                );
                              })}
                            </ul>
                          )}
                          {rule.action === 'route' ? (
                            <div className="row-inline">
                              <select
                                className="input input--small"
                                aria-label={t('admin.catchallAssign')}
                                value={ruleAssignee[rule.domain] ?? ''}
                                onChange={(event) =>
                                  setRuleAssignee((current) => ({
                                    ...current,
                                    [rule.domain]: event.target.value,
                                  }))
                                }
                              >
                                <option value="">—</option>
                                {ruleTargets
                                  .filter(
                                    (member) =>
                                      !(rule.assignments ?? []).some(
                                        (assignment) => assignment.account_id === member.account_id,
                                      ),
                                  )
                                  .map((member) => (
                                    <option
                                      key={member.account_id}
                                      value={String(member.account_id)}
                                    >
                                      {member.email}
                                    </option>
                                  ))}
                              </select>
                              <button
                                type="button"
                                className="btn btn--small btn--ghost"
                                onClick={() => addCatchallAssignee(rule.domain)}
                                disabled={(ruleAssignee[rule.domain] ?? '').length === 0}
                              >
                                <UserPlus size={13} aria-hidden="true" />
                                {t('admin.catchallAssign')}
                              </button>
                            </div>
                          ) : null}
                        </td>
                        <td>
                          <div className="admin-table__actions">
                            <button
                              type="button"
                              className={`btn btn--small ${
                                pendingRule === rule.domain ? 'btn--danger' : 'btn--ghost'
                              }`}
                              onClick={() => removeRule(rule)}
                              disabled={busyRule === rule.domain}
                            >
                              {busyRule === rule.domain ? (
                                <Loader2 size={14} className="spin" aria-hidden="true" />
                              ) : (
                                <Trash2 size={14} aria-hidden="true" />
                              )}
                              {pendingRule === rule.domain
                                ? `${t('common.delete')}?`
                                : t('common.delete')}
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : null}

            <form className="settings__form admin__ruleform" onSubmit={submitRule}>
              <label className="field field--plain">
                <span className="field__label">{t('admin.catchallDomain')}</span>
                <input
                  className="input"
                  type="text"
                  value={ruleDomain}
                  placeholder="example.org"
                  onChange={(event) => {
                    setRuleDomain(event.target.value);
                    setRuleTarget('');
                  }}
                />
              </label>
              <label className="field field--plain">
                <span className="field__label">{t('admin.catchallAction')}</span>
                <select
                  className="input"
                  value={ruleAction}
                  onChange={(event) => setRuleAction(event.target.value as CatchallAction)}
                >
                  <option value="route">{t('admin.actionRoute')}</option>
                  <option value="discard">{t('admin.actionDiscard')}</option>
                </select>
              </label>
              {ruleAction === 'route' ? (
                <label className="field field--plain">
                  <span className="field__label">{t('admin.catchallTarget')}</span>
                  <select
                    className="input"
                    value={ruleTarget}
                    onChange={(event) => setRuleTarget(event.target.value)}
                  >
                    <option value="">—</option>
                    {ruleTargets.map((member) => (
                      <option key={member.account_id} value={String(member.account_id)}>
                        {member.email}
                      </option>
                    ))}
                  </select>
                  {ruleTargets.length === 0 ? (
                    <span className="admin__hint">{t('admin.catchallNoTarget')}</span>
                  ) : null}
                </label>
              ) : null}
              {ruleError !== null ? (
                <p className="field__error" role="alert">
                  {ruleError}
                </p>
              ) : null}
              <button
                type="submit"
                className="btn btn--primary"
                disabled={
                  savingRule ||
                  ruleDomain.trim().length === 0 ||
                  (ruleAction === 'route' && ruleTarget.length === 0)
                }
              >
                {savingRule ? (
                  <Loader2 size={15} className="spin" aria-hidden="true" />
                ) : (
                  <Plus size={15} aria-hidden="true" />
                )}
                {t('admin.catchall')}
              </button>
            </form>
          </section>
        ) : null}

        {canAdminister ? (
          <section className="panel">
            <div className="panel__head">
              <h2>
                <AtSign size={15} aria-hidden="true" />
                {t('admin.aliasTitle')}
              </h2>
              <p>{t('admin.aliasBody')}</p>
            </div>

            {aliasesState === 'loading' || aliasesState === 'idle' ? loadingBlock : null}
            {aliasesState === 'error' || aliasesState === 'forbidden'
              ? errorBlock(() => setAliasesToken((token) => token + 1))
              : null}

            {aliasesState === 'ready' && aliases.length > 0 ? (
              <div className="admin-table__wrap">
                <table className="admin-table">
                  <thead>
                    <tr>
                      <th scope="col">{t('admin.aliasAddress')}</th>
                      <th scope="col">{t('admin.aliasAssignees')}</th>
                      <th scope="col" />
                    </tr>
                  </thead>
                  <tbody>
                    {aliases.map((alias) => (
                      <tr key={alias.id}>
                        <td className="admin-table__email mono">{alias.address}</td>
                        <td className="admin-table__meta">
                          {alias.assignments.length === 0 ? (
                            <span className="admin__hint">{t('admin.aliasNoAssignees')}</span>
                          ) : (
                            <ul className="tag-list">
                              {alias.assignments.map((assignment) => {
                                const key = `alias:${alias.id}:${assignment.account_id}`;
                                return (
                                  <li key={assignment.account_id} className="badge badge--enc">
                                    {assignment.email ??
                                      emailOf.get(assignment.account_id) ??
                                      `#${assignment.account_id}`}
                                    <button
                                      type="button"
                                      className="icon-btn icon-btn--tiny"
                                      onClick={() => dropAliasAssignee(alias, assignment.account_id)}
                                      disabled={busyAssignee === key}
                                      aria-label={t('admin.aliasUnassign')}
                                      title={t('admin.aliasUnassign')}
                                    >
                                      <UserMinus size={12} aria-hidden="true" />
                                    </button>
                                  </li>
                                );
                              })}
                            </ul>
                          )}
                          <div className="row-inline">
                            <select
                              className="input input--small"
                              aria-label={t('admin.aliasAssign')}
                              value={aliasAssignee[alias.id] ?? ''}
                              onChange={(event) =>
                                setAliasAssignee((current) => ({
                                  ...current,
                                  [alias.id]: event.target.value,
                                }))
                              }
                            >
                              <option value="">—</option>
                              {members
                                .filter(
                                  (member) =>
                                    !alias.assignments.some(
                                      (assignment) => assignment.account_id === member.account_id,
                                    ),
                                )
                                .map((member) => (
                                  <option key={member.account_id} value={String(member.account_id)}>
                                    {member.email}
                                  </option>
                                ))}
                            </select>
                            <button
                              type="button"
                              className="btn btn--small btn--ghost"
                              onClick={() => addAliasAssignee(alias)}
                              disabled={(aliasAssignee[alias.id] ?? '').length === 0}
                            >
                              <UserPlus size={13} aria-hidden="true" />
                              {t('admin.aliasAssign')}
                            </button>
                          </div>
                        </td>
                        <td>
                          <div className="admin-table__actions">
                            <button
                              type="button"
                              className={`btn btn--small ${
                                pendingAlias === alias.id ? 'btn--danger' : 'btn--ghost'
                              }`}
                              onClick={() => removeAlias(alias)}
                              disabled={busyAlias === alias.id}
                            >
                              {busyAlias === alias.id ? (
                                <Loader2 size={14} className="spin" aria-hidden="true" />
                              ) : (
                                <Trash2 size={14} aria-hidden="true" />
                              )}
                              {pendingAlias === alias.id
                                ? `${t('common.delete')}?`
                                : t('common.delete')}
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : null}

            <form className="settings__form admin__ruleform" onSubmit={submitAlias}>
              <label className="field field--plain">
                <span className="field__label">{t('admin.aliasAddress')}</span>
                <input
                  className="input"
                  type="email"
                  value={newAlias}
                  placeholder="sales@example.org"
                  onChange={(event) => setNewAlias(event.target.value)}
                />
              </label>
              {aliasError !== null ? (
                <p className="field__error" role="alert">
                  {aliasError}
                </p>
              ) : null}
              <button
                type="submit"
                className="btn btn--primary"
                disabled={creatingAlias || newAlias.trim().length === 0}
              >
                {creatingAlias ? (
                  <Loader2 size={15} className="spin" aria-hidden="true" />
                ) : (
                  <Plus size={15} aria-hidden="true" />
                )}
                {t('admin.aliasCreate')}
              </button>
            </form>
          </section>
        ) : null}
      </div>
    </section>
  );
}

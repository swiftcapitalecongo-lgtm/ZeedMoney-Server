-- ZedMoney: safe, additive withdrawal cancellation migration
-- Run this once in Supabase SQL Editor after the base schema exists.
-- It does not alter existing wallet balances or existing ledger rows.

begin;

insert into public.admin_permissions(name)
values ('withdrawals.manage')
on conflict (name) do nothing;

insert into public.admin_role_permissions(role_id, permission_id)
select r.id, p.id
from public.admin_roles r
cross join public.admin_permissions p
where r.name = 'Super Admin'
  and p.name = 'withdrawals.manage'
on conflict do nothing;

create or replace function public.admin_cancel_withdrawal(
  p_withdrawal_id uuid,
  p_admin_user_id uuid,
  p_reason text,
  p_note text default null
) returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  w public.withdrawals%rowtype;
  tx public.transactions%rowtype;
  wallet public.wallets%rowtype;
  release_tx public.transactions%rowtype;
  before_available numeric;
  after_available numeric;
  before_reserved numeric;
  after_reserved numeric;
  release_reference text;
begin
  -- p_admin_user_id is the primary key from public.admin_users, not auth.users.id.
  if not exists (
    select 1
    from public.admin_users
    where id = p_admin_user_id
      and active = true
  ) then
    raise exception 'Administrator authorization required';
  end if;

  if p_reason is null or length(trim(p_reason)) < 3 then
    raise exception 'A cancellation reason is required';
  end if;

  select *
  into w
  from public.withdrawals
  where id = p_withdrawal_id
  for update;

  if w.id is null then
    raise exception 'Withdrawal not found';
  end if;

  -- Safe retry: do not create a second release if the request was repeated.
  if w.status = 'cancelled' then
    return jsonb_build_object(
      'already_cancelled', true,
      'withdrawal_id', w.id,
      'status', w.status
    );
  end if;

  -- Once claimed or submitted, provider reconciliation must handle it.
  if w.status <> 'pending' or w.provider_reference is not null then
    raise exception 'This withdrawal is already being processed and cannot be cancelled';
  end if;

  select *
  into tx
  from public.transactions
  where user_id = w.user_id
    and type = 'withdrawal'
    and metadata->>'withdrawal_id' = w.id::text
  order by created_at desc
  limit 1
  for update;

  if tx.id is null then
    raise exception 'Withdrawal transaction not found';
  end if;

  select *
  into wallet
  from public.wallets
  where user_id = w.user_id
  for update;

  if wallet.id is null then
    raise exception 'Wallet not found';
  end if;

  before_available := wallet.available_balance;
  after_available := before_available + w.amount;
  before_reserved := wallet.reserved_balance;
  after_reserved := before_reserved - w.amount;

  if before_reserved < w.amount then
    raise exception 'Reserved wallet balance is inconsistent with this withdrawal';
  end if;

  release_reference :=
    'WD-REL-' || upper(substr(replace(gen_random_uuid()::text, '-', ''), 1, 12));

  update public.wallets
  set available_balance = after_available,
      reserved_balance = after_reserved,
      updated_at = now()
  where id = wallet.id;

  update public.withdrawals
  set status = 'cancelled',
      updated_at = now()
  where id = w.id;

  update public.transactions
  set status = 'cancelled',
      completed_at = now(),
      updated_at = now()
  where id = tx.id;

  insert into public.transactions(
    reference, user_id, wallet_id, type, status, amount, fee, net_amount,
    currency, description, metadata, completed_at
  )
  values (
    release_reference, w.user_id, wallet.id, 'release', 'successful',
    w.amount, 0, w.amount, w.currency,
    'Reserved funds returned after withdrawal cancellation',
    jsonb_build_object(
      'withdrawal_release', true,
      'withdrawal_id', w.id,
      'cancelled_transaction_id', tx.id
    ),
    now()
  )
  returning * into release_tx;

  insert into public.ledger_entries(
    wallet_id, transaction_id, entry_type, direction, amount, currency,
    balance_before, balance_after, reference, description, metadata
  )
  values (
    wallet.id, release_tx.id, 'withdrawal_release', 'credit', w.amount,
    w.currency, before_available, after_available, release_reference,
    'Reserved funds returned after withdrawal cancellation',
    jsonb_build_object(
      'withdrawal_id', w.id,
      'cancelled_transaction_id', tx.id
    )
  );

  insert into public.audit_logs(
    admin_user_id, action, target_type, target_id, reason, note, metadata
  )
  values (
    p_admin_user_id, 'CANCEL_WITHDRAWAL', 'withdrawal', w.id,
    trim(p_reason), nullif(trim(p_note), ''),
    jsonb_build_object(
      'withdrawal_id', w.id,
      'transaction_id', tx.id,
      'release_transaction_id', release_tx.id,
      'amount', w.amount
    )
  );

  insert into public.notifications(
    user_id, type, title, message, metadata
  )
  values (
    w.user_id,
    'withdrawal_cancelled',
    'Withdrawal declined',
    'Your withdrawal was declined and ' ||
      w.currency || ' ' ||
      to_char(w.amount, 'FM999999990.00') ||
      ' was returned to your available wallet balance.',
    jsonb_build_object(
      'withdrawal_id', w.id,
      'transaction_id', tx.id,
      'release_transaction_id', release_tx.id
    )
  );

  return jsonb_build_object(
    'already_cancelled', false,
    'withdrawal_id', w.id,
    'transaction_id', tx.id,
    'release_transaction_id', release_tx.id,
    'status', 'cancelled',
    'returned_amount', w.amount
  );
end;
$$;

-- The server calls this through its service-role client. Do not expose this
-- balance-changing RPC directly to browser roles.
revoke execute on function public.admin_cancel_withdrawal(uuid, uuid, text, text)
from public, anon, authenticated;
grant execute on function public.admin_cancel_withdrawal(uuid, uuid, text, text)
to service_role;

commit;
-- ZedMoney signup-bonus control
-- Run this once in the Supabase SQL Editor after the existing schema.
-- This migration is additive and safe to run more than once.
-- It changes future signups only; it does not alter existing wallets.

begin;

create table if not exists public.bonus_settings (
  id boolean primary key default true check (id = true),
  enabled boolean not null default true,
  amount numeric(20,2) not null default 5 check (amount >= 0),
  currency text not null default 'ZMW' check (char_length(currency) = 3),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table public.bonus_settings add column if not exists enabled boolean not null default true;
alter table public.bonus_settings add column if not exists amount numeric(20,2) not null default 5;
alter table public.bonus_settings add column if not exists currency text not null default 'ZMW';
alter table public.bonus_settings add column if not exists created_at timestamptz not null default now();
alter table public.bonus_settings add column if not exists updated_at timestamptz not null default now();

insert into public.bonus_settings (id, enabled, amount, currency)
values (true, true, 5, 'ZMW')
on conflict (id) do nothing;

insert into public.admin_permissions(name)
values ('bonus.read'), ('bonus.manage'), ('bonus.deduct')
on conflict (name) do nothing;

insert into public.admin_role_permissions(role_id, permission_id)
select r.id, p.id
from public.admin_roles r
cross join public.admin_permissions p
where r.name = 'Super Admin'
  and p.name in ('bonus.read', 'bonus.manage', 'bonus.deduct')
on conflict do nothing;

commit;

-- The original schema hard-codes K5 in this trigger. Replace only the
-- function; the existing on_auth_user_created trigger will use this version.
create or replace function public.handle_new_user() returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  new_profile_id uuid := new.id;
  wallet_id uuid;
  welcome_transaction_id uuid;
  configured_bonus public.bonus_settings%rowtype;
  bonus_amount numeric(20,2);
  bonus_currency text;
begin
  select *
  into configured_bonus
  from public.bonus_settings
  where id = true;

  bonus_amount := case
    when coalesce(configured_bonus.enabled, false)
      then coalesce(configured_bonus.amount, 0)
    else 0
  end;
  bonus_currency := coalesce(configured_bonus.currency, 'ZMW');

  insert into public.profiles(
    id, first_name, last_name, display_name, username, phone, zedmoney_id
  )
  values (
    new_profile_id,
    coalesce(new.raw_user_meta_data->>'first_name', ''),
    coalesce(new.raw_user_meta_data->>'last_name', ''),
    nullif(
      trim(
        coalesce(new.raw_user_meta_data->>'first_name', '') || ' ' ||
        coalesce(new.raw_user_meta_data->>'last_name', '')
      ),
      ''
    ),
    nullif(lower(trim(new.raw_user_meta_data->>'username')), ''),
    nullif(new.raw_user_meta_data->>'phone', ''),
    public.new_zedmoney_id()
  )
  on conflict (id) do nothing;

  insert into public.wallets(
    user_id, wallet_identifier, currency, available_balance
  )
  values (
    new_profile_id,
    'ZW-' || upper(substr(replace(gen_random_uuid()::text, '-', ''), 1, 12)),
    bonus_currency,
    bonus_amount
  )
  on conflict (user_id) do nothing;

  select id into wallet_id
  from public.wallets
  where user_id = new_profile_id;

  insert into public.wallet_limits(user_id)
  values (new_profile_id)
  on conflict (user_id) do nothing;

  if bonus_amount > 0 then
    insert into public.transactions(
      reference, user_id, wallet_id, type, status, amount, fee, net_amount,
      currency, description, metadata, completed_at
    )
    select
      'WELCOME-' || upper(substr(replace(new_profile_id::text, '-', ''), 1, 12)),
      new_profile_id,
      wallet_id,
      'adjustment',
      'successful',
      bonus_amount,
      0,
      bonus_amount,
      bonus_currency,
      'ZedMoney welcome bonus',
      jsonb_build_object(
        'welcome_bonus', true,
        'amount', bonus_amount,
        'currency', bonus_currency
      ),
      now()
    where not exists (
      select 1
      from public.transactions t
      where t.reference =
        'WELCOME-' || upper(substr(replace(new_profile_id::text, '-', ''), 1, 12))
    )
    returning id into welcome_transaction_id;

    if welcome_transaction_id is not null then
      insert into public.ledger_entries(
        wallet_id, transaction_id, entry_type, direction, amount, currency,
        balance_before, balance_after, reference, description, metadata
      )
      values (
        wallet_id,
        welcome_transaction_id,
        'welcome_bonus',
        'credit',
        bonus_amount,
        bonus_currency,
        0,
        bonus_amount,
        'WELCOME-' || upper(substr(replace(new_profile_id::text, '-', ''), 1, 12)),
        'ZedMoney welcome bonus',
        jsonb_build_object(
          'welcome_bonus', true,
          'amount', bonus_amount,
          'currency', bonus_currency
        )
      );

      insert into public.notifications(
        user_id, type, title, message, metadata
      )
      values (
        new_profile_id,
        'welcome_bonus',
        'Welcome to ZedMoney',
        'Your ' || bonus_currency || ' ' ||
          to_char(bonus_amount, 'FM999999990.00') ||
          ' welcome bonus is ready. Add funds to keep building your wallet.',
        jsonb_build_object(
          'welcome_bonus', true,
          'amount', bonus_amount,
          'currency', bonus_currency,
          'action', 'add_funds'
        )
      );
    end if;
  end if;

  return new;
end;
$$;

-- Decline a pending withdrawal before Lipila receives the payout. This is the
-- internal cancellation/refund path: reserved funds return to available
-- balance, while the original reserve remains immutable in the ledger.
create or replace function public.admin_cancel_withdrawal(
  p_withdrawal_id uuid,
  p_admin_user_id uuid,
  p_reason text,
  p_note text default null
) returns jsonb
language plpgsql security definer set search_path=public as $$
declare
  w public.withdrawals%rowtype;
  tx public.transactions%rowtype;
  wallet public.wallets%rowtype;
  before_available numeric;
  after_available numeric;
  before_reserved numeric;
  after_reserved numeric;
  release_tx public.transactions%rowtype;
  release_reference text;
begin
  if not exists (select 1 from public.admin_users where id=p_admin_user_id and active=true) then
    raise exception 'Administrator authorization required';
  end if;
  if p_reason is null or length(trim(p_reason)) < 3 then
    raise exception 'A cancellation reason is required';
  end if;
  select * into w from public.withdrawals where id=p_withdrawal_id for update;
  if w.id is null then raise exception 'Withdrawal not found'; end if;
  if w.status = 'cancelled' then
    return jsonb_build_object('already_cancelled',true,'withdrawal_id',w.id,'status',w.status);
  end if;
  if w.status <> 'pending' or w.provider_reference is not null then
    raise exception 'This withdrawal is already being processed and cannot be cancelled';
  end if;
  select * into tx from public.transactions
  where user_id=w.user_id and type='withdrawal' and metadata->>'withdrawal_id'=w.id::text
  order by created_at desc limit 1 for update;
  if tx.id is null then raise exception 'Withdrawal transaction not found'; end if;
  select * into wallet from public.wallets where user_id=w.user_id for update;
  if wallet.id is null then raise exception 'Wallet not found'; end if;
  before_available := wallet.available_balance;
  before_reserved := wallet.reserved_balance;
  if before_reserved < w.amount then raise exception 'Reserved wallet balance is inconsistent with this withdrawal'; end if;
  after_available := before_available + w.amount;
  after_reserved := before_reserved - w.amount;
  release_reference := 'WD-REL-' || upper(substr(replace(gen_random_uuid()::text,'-',''),1,12));
  update public.wallets set available_balance=after_available,reserved_balance=after_reserved,updated_at=now() where id=wallet.id;
  update public.withdrawals set status='cancelled',updated_at=now() where id=w.id;
  update public.transactions set status='cancelled',completed_at=now(),updated_at=now() where id=tx.id;
  insert into public.transactions(reference,user_id,wallet_id,type,status,amount,fee,net_amount,currency,description,metadata,completed_at)
  values (release_reference,w.user_id,wallet.id,'release','successful',w.amount,0,w.amount,w.currency,
    'Reserved funds returned after withdrawal cancellation',
    jsonb_build_object('withdrawal_release',true,'withdrawal_id',w.id,'cancelled_transaction_id',tx.id),now())
  returning * into release_tx;
  insert into public.ledger_entries(wallet_id,transaction_id,entry_type,direction,amount,currency,balance_before,balance_after,reference,description,metadata)
  values (wallet.id,release_tx.id,'withdrawal_release','credit',w.amount,w.currency,before_available,after_available,
    release_reference,'Reserved funds returned after withdrawal cancellation',
    jsonb_build_object('withdrawal_id',w.id,'cancelled_transaction_id',tx.id));
  insert into public.audit_logs(admin_user_id,action,target_type,target_id,reason,note,metadata)
  values (p_admin_user_id,'CANCEL_WITHDRAWAL','withdrawal',w.id,p_reason,p_note,
    jsonb_build_object('withdrawal_id',w.id,'transaction_id',tx.id,'release_transaction_id',release_tx.id,'amount',w.amount));
  insert into public.notifications(user_id,type,title,message,metadata)
  values (w.user_id,'withdrawal_cancelled','Withdrawal declined',
    'Your withdrawal was declined and '||w.currency||' '||to_char(w.amount,'FM999999990.00')||' was returned to your available wallet balance.',
    jsonb_build_object('withdrawal_id',w.id,'transaction_id',tx.id,'release_transaction_id',release_tx.id));
  return jsonb_build_object('already_cancelled',false,'withdrawal_id',w.id,'transaction_id',tx.id,
    'release_transaction_id',release_tx.id,'status','cancelled','returned_amount',w.amount);
end;
$$;

revoke execute on function public.admin_cancel_withdrawal(uuid, uuid, text, text)
from public, anon, authenticated;
grant execute on function public.admin_cancel_withdrawal(uuid, uuid, text, text)
to service_role;

create or replace function public.admin_deduct_signup_bonus(
  p_bonus_transaction_id uuid,
  p_admin_user_id uuid
) returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  bonus_tx public.transactions%rowtype;
  existing_deduction public.transactions%rowtype;
  wallet public.wallets%rowtype;
  deduction_tx public.transactions%rowtype;
  before_available numeric;
  after_available numeric;
  deduction_reference text;
begin
  if not exists (
    select 1 from public.admin_users
    where user_id = p_admin_user_id and active = true
  ) then
    raise exception 'Administrator authorization required';
  end if;

  select *
  into bonus_tx
  from public.transactions
  where id = p_bonus_transaction_id
    and type = 'adjustment'
    and metadata->>'welcome_bonus' = 'true'
  for update;

  if bonus_tx.id is null then
    raise exception 'Signup bonus transaction not found';
  end if;

  select *
  into existing_deduction
  from public.transactions
  where metadata->>'signup_bonus_deduction_of' = bonus_tx.id::text
  limit 1;

  if existing_deduction.id is not null then
    return jsonb_build_object(
      'already_deducted', true,
      'transaction_id', existing_deduction.id,
      'bonus_transaction_id', bonus_tx.id,
      'status', existing_deduction.status
    );
  end if;

  select *
  into wallet
  from public.wallets
  where id = bonus_tx.wallet_id
  for update;

  if wallet.id is null then
    raise exception 'Wallet not found';
  end if;

  before_available := wallet.available_balance;
  if before_available < bonus_tx.amount then
    raise exception 'The wallet does not have enough available funds to deduct this bonus';
  end if;
  after_available := before_available - bonus_tx.amount;
  deduction_reference :=
    'BONUS-REV-' || upper(substr(replace(gen_random_uuid()::text, '-', ''), 1, 12));

  insert into public.transactions(
    reference, user_id, wallet_id, type, status, amount, fee, net_amount,
    currency, description, metadata, completed_at
  )
  values (
    deduction_reference,
    bonus_tx.user_id,
    wallet.id,
    'adjustment',
    'successful',
    bonus_tx.amount,
    0,
    bonus_tx.amount,
    wallet.currency,
    'Signup bonus deducted by administrator',
    jsonb_build_object(
      'signup_bonus_deduction', true,
      'signup_bonus_deduction_of', bonus_tx.id,
      'amount', bonus_tx.amount,
      'currency', wallet.currency
    ),
    now()
  )
  returning * into deduction_tx;

  update public.wallets
  set available_balance = after_available, updated_at = now()
  where id = wallet.id;

  insert into public.ledger_entries(
    wallet_id, transaction_id, entry_type, direction, amount, currency,
    balance_before, balance_after, reference, description, metadata
  )
  values (
    wallet.id,
    deduction_tx.id,
    'signup_bonus_deduction',
    'debit',
    bonus_tx.amount,
    wallet.currency,
    before_available,
    after_available,
    deduction_reference,
    'Signup bonus deducted by administrator',
    jsonb_build_object('signup_bonus_transaction_id', bonus_tx.id)
  );

  insert into public.audit_logs(
    admin_user_id, action, target_type, target_id, reason, metadata
  )
  values (
    p_admin_user_id,
    'DEDUCT_SIGNUP_BONUS',
    'user',
    bonus_tx.user_id,
    'Signup bonus deducted by administrator',
    jsonb_build_object(
      'bonus_transaction_id', bonus_tx.id,
      'deduction_transaction_id', deduction_tx.id,
      'amount', bonus_tx.amount
    )
  );

  insert into public.notifications(
    user_id, type, title, message, metadata
  )
  values (
    bonus_tx.user_id,
    'welcome_bonus_deducted',
    'Signup bonus adjusted',
    'Your signup bonus was removed by an administrator adjustment.',
    jsonb_build_object(
      'bonus_transaction_id', bonus_tx.id,
      'deduction_transaction_id', deduction_tx.id,
      'amount', bonus_tx.amount
    )
  );

  return jsonb_build_object(
    'already_deducted', false,
    'transaction_id', deduction_tx.id,
    'bonus_transaction_id', bonus_tx.id,
    'amount', bonus_tx.amount,
    'status', 'successful'
  );
end;
$$;
-- ZedMoney / Lipila additive migration
--
-- Run this AFTER the existing full supabase-setup.md schema.
-- Signup-bonus and withdrawal-cancellation changes live in their dedicated
-- migration files; this file contains only Lipila-related additions.
-- It is safe to run more than once.

begin;

-- Provider-reference indexes support callbacks, status checks and monitoring.
create index if not exists transactions_lipila_provider_reference_idx
  on public.transactions(provider, provider_reference)
  where provider is not null and provider_reference is not null;

create index if not exists deposits_lipila_provider_reference_idx
  on public.deposits(provider, provider_reference)
  where provider is not null and provider_reference is not null;

create index if not exists payment_link_payments_provider_reference_idx
  on public.payment_link_payments(provider, provider_reference)
  where provider is not null and provider_reference is not null;

create index if not exists provider_webhook_events_processing_idx
  on public.provider_webhook_events(provider, processing_status, received_at desc);

insert into public.admin_permissions(name)
values ('notifications.read')
on conflict (name) do nothing;

commit;

-- Lipila deposit lifecycle and atomic wallet settlement.
-- These additions support the Created -> Processing -> Pending -> terminal
-- lifecycle without changing the base wallet or transaction schema.
begin;

alter table public.deposits
  add column if not exists metadata jsonb not null default '{}';

do $$
declare
  constraint_name text;
begin
  for constraint_name in
    select conname
    from pg_constraint
    where conrelid = 'public.deposits'::regclass
      and contype = 'c'
      and pg_get_constraintdef(oid) ilike '%status%'
  loop
    execute format('alter table public.deposits drop constraint %I', constraint_name);
  end loop;
end $$;

alter table public.deposits
  add constraint deposits_status_check
  check (status in ('created','pending','processing','successful','failed','cancelled','reversed'));

create index if not exists deposits_provider_reference
  on public.deposits(provider, provider_reference)
  where provider_reference is not null;

create or replace function public.mark_deposit_pending(
  p_deposit_id uuid,
  p_transaction_id uuid
) returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  tx public.transactions%rowtype;
  wallet public.wallets%rowtype;
  amount numeric(20,2);
begin
  select * into tx from public.transactions
  where id = p_transaction_id and type = 'deposit'
  for update;
  if tx.id is null then raise exception 'Deposit transaction not found'; end if;
  if coalesce(tx.metadata->>'pending_reserved', 'false') = 'true' then
    return jsonb_build_object('already_reserved', true, 'transaction_id', tx.id);
  end if;

  select * into wallet from public.wallets where id = tx.wallet_id for update;
  if wallet.id is null then raise exception 'Wallet not found'; end if;
  amount := coalesce(tx.net_amount, tx.amount);

  update public.wallets
  set pending_balance = coalesce(pending_balance, 0) + amount,
      updated_at = now()
  where id = wallet.id;

  update public.transactions
  set metadata = coalesce(metadata, '{}'::jsonb) ||
      jsonb_build_object('pending_reserved', true, 'state', 'processing'),
      updated_at = now()
  where id = tx.id;

  update public.deposits
  set metadata = coalesce(metadata, '{}'::jsonb) ||
      jsonb_build_object('state', 'processing'),
      status = 'processing',
      updated_at = now()
  where id = p_deposit_id;

  return jsonb_build_object('already_reserved', false, 'transaction_id', tx.id);
end;
$$;

create or replace function public.finalize_deposit(
  p_deposit_id uuid,
  p_transaction_id uuid,
  p_status text,
  p_provider_reference text default null,
  p_provider_message text default null,
  p_provider_payload jsonb default '{}'::jsonb,
  p_event_id text default null
) returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  tx public.transactions%rowtype;
  deposit public.deposits%rowtype;
  wallet public.wallets%rowtype;
  before_available numeric(20,2);
  after_available numeric(20,2);
  amount numeric(20,2);
  terminal_status text := lower(trim(p_status));
begin
  if terminal_status not in ('successful','failed','cancelled','reversed') then
    raise exception 'Invalid terminal deposit status';
  end if;

  select * into tx from public.transactions
  where id = p_transaction_id and type = 'deposit'
  for update;
  if tx.id is null then raise exception 'Deposit transaction not found'; end if;

  if tx.status in ('successful','failed','cancelled','reversed') then
    return jsonb_build_object(
      'already_processed', true,
      'transaction_id', tx.id,
      'status', tx.status
    );
  end if;

  select * into deposit from public.deposits
  where id = p_deposit_id
  for update;
  if deposit.id is null then raise exception 'Deposit not found'; end if;

  select * into wallet from public.wallets where id = tx.wallet_id for update;
  if wallet.id is null then raise exception 'Wallet not found'; end if;
  amount := coalesce(tx.net_amount, tx.amount);
  before_available := coalesce(wallet.available_balance, 0);
  after_available := before_available;

  if coalesce(tx.metadata->>'pending_reserved', 'false') = 'true' then
    update public.wallets
    set pending_balance = greatest(coalesce(pending_balance, 0) - amount, 0),
        updated_at = now()
    where id = wallet.id;
  end if;

  if terminal_status = 'successful' then
    after_available := before_available + amount;
    update public.wallets
    set available_balance = after_available,
        updated_at = now()
    where id = wallet.id;

    insert into public.ledger_entries(
      wallet_id, transaction_id, entry_type, direction, amount, currency,
      balance_before, balance_after, reference, description, metadata
    ) values (
      wallet.id, tx.id, 'deposit', 'credit', amount, tx.currency,
      before_available, after_available, tx.reference,
      coalesce(tx.description, 'Mobile-money deposit'),
      jsonb_build_object(
        'provider', 'lipila',
        'provider_reference', p_provider_reference,
        'provider_message', p_provider_message,
        'event_id', p_event_id
      )
    );
  end if;

  update public.transactions
  set status = terminal_status::public.transaction_status,
      provider = 'lipila',
      provider_reference = coalesce(p_provider_reference, provider_reference),
      completed_at = now(),
      updated_at = now(),
      metadata = coalesce(metadata, '{}'::jsonb) ||
        jsonb_build_object(
          'state', terminal_status,
          'provider_message', coalesce(p_provider_message, ''),
          'provider_response', coalesce(p_provider_payload, '{}'::jsonb),
          'terminal_at', now(),
          'event_id', p_event_id
        )
  where id = tx.id;

  update public.deposits
  set status = terminal_status,
      provider = 'lipila',
      provider_reference = coalesce(p_provider_reference, provider_reference),
      updated_at = now(),
      metadata = coalesce(metadata, '{}'::jsonb) ||
        jsonb_build_object(
          'state', terminal_status,
          'provider_message', coalesce(p_provider_message, ''),
          'provider_response', coalesce(p_provider_payload, '{}'::jsonb),
          'terminal_at', now(),
          'event_id', p_event_id
        )
  where id = deposit.id;

  insert into public.notifications(user_id, type, title, message, metadata)
  values (
    tx.user_id,
    case when terminal_status = 'successful' then 'deposit_success' else 'deposit_failed' end,
    case when terminal_status = 'successful' then 'Deposit successful' else 'Deposit not completed' end,
    case
      when terminal_status = 'successful'
        then tx.currency || ' ' || to_char(amount, 'FM999999990.00') || ' has been added to your wallet.'
      else coalesce(nullif(p_provider_message, ''), 'Your mobile-money deposit could not be completed.')
    end,
    jsonb_build_object(
      'transaction_id', tx.id,
      'deposit_id', deposit.id,
      'provider_reference', p_provider_reference,
      'provider_status', terminal_status
    )
  );

  return jsonb_build_object(
    'already_processed', false,
    'transaction_id', tx.id,
    'deposit_id', deposit.id,
    'status', terminal_status,
    'provider_reference', p_provider_reference,
    'provider_message', p_provider_message
  );
end;
$$;

revoke execute on function public.mark_deposit_pending(uuid, uuid)
from public, anon, authenticated;
revoke execute on function public.finalize_deposit(uuid, uuid, text, text, text, jsonb, text)
from public, anon, authenticated;
grant execute on function public.mark_deposit_pending(uuid, uuid) to service_role;
grant execute on function public.finalize_deposit(uuid, uuid, text, text, text, jsonb, text) to service_role;

commit;

-- Decline a pending withdrawal before the provider request is sent. This is
-- the internal cancellation/refund path: reserved funds return to available
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
  if not exists (
    select 1 from public.admin_users
    where id=p_admin_user_id and active=true
  ) then
    raise exception 'Administrator authorization required';
  end if;
  if p_reason is null or length(trim(p_reason)) < 3 then
    raise exception 'A cancellation reason is required';
  end if;

  select * into w from public.withdrawals
  where id=p_withdrawal_id for update;
  if w.id is null then raise exception 'Withdrawal not found'; end if;
  if w.status = 'cancelled' then
    return jsonb_build_object('already_cancelled',true,'withdrawal_id',w.id,'status',w.status);
  end if;
  if w.status <> 'pending' or w.provider_reference is not null then
    raise exception 'This withdrawal is already being processed and cannot be cancelled';
  end if;

  select * into tx from public.transactions
  where user_id=w.user_id and type='withdrawal'
    and metadata->>'withdrawal_id'=w.id::text
  order by created_at desc limit 1 for update;
  if tx.id is null then raise exception 'Withdrawal transaction not found'; end if;

  select * into wallet from public.wallets where user_id=w.user_id for update;
  if wallet.id is null then raise exception 'Wallet not found'; end if;
  before_available := wallet.available_balance;
  before_reserved := wallet.reserved_balance;
  if before_reserved < w.amount then
    raise exception 'Reserved wallet balance is inconsistent with this withdrawal';
  end if;
  after_available := before_available + w.amount;
  after_reserved := before_reserved - w.amount;
  release_reference := 'WD-REL-' || upper(substr(replace(gen_random_uuid()::text,'-',''),1,12));

  update public.wallets
  set available_balance=after_available,reserved_balance=after_reserved,updated_at=now()
  where id=wallet.id;
  update public.withdrawals set status='cancelled',updated_at=now() where id=w.id;
  update public.transactions set status='cancelled',completed_at=now(),updated_at=now() where id=tx.id;

  insert into public.transactions(
    reference,user_id,wallet_id,type,status,amount,fee,net_amount,currency,
    description,metadata,completed_at
  ) values (
    release_reference,w.user_id,wallet.id,'release','successful',w.amount,0,w.amount,
    w.currency,'Reserved funds returned after withdrawal cancellation',
    jsonb_build_object('withdrawal_release',true,'withdrawal_id',w.id,'cancelled_transaction_id',tx.id),
    now()
  ) returning * into release_tx;

  insert into public.ledger_entries(
    wallet_id,transaction_id,entry_type,direction,amount,currency,
    balance_before,balance_after,reference,description,metadata
  ) values (
    wallet.id,release_tx.id,'withdrawal_release','credit',w.amount,w.currency,
    before_available,after_available,release_reference,
    'Reserved funds returned after withdrawal cancellation',
    jsonb_build_object('withdrawal_id',w.id,'cancelled_transaction_id',tx.id)
  );

  insert into public.audit_logs(
    admin_user_id,action,target_type,target_id,reason,note,metadata
  ) values (
    p_admin_user_id,'CANCEL_WITHDRAWAL','withdrawal',w.id,p_reason,p_note,
    jsonb_build_object('withdrawal_id',w.id,'transaction_id',tx.id,'release_transaction_id',release_tx.id,'amount',w.amount)
  );
  insert into public.notifications(user_id,type,title,message,metadata)
  values (
    w.user_id,'withdrawal_cancelled','Withdrawal declined',
    'Your withdrawal was declined and '||w.currency||' '||to_char(w.amount,'FM999999990.00')||' was returned to your available wallet balance.',
    jsonb_build_object('withdrawal_id',w.id,'transaction_id',tx.id,'release_transaction_id',release_tx.id)
  );
  return jsonb_build_object(
    'already_cancelled',false,'withdrawal_id',w.id,'transaction_id',tx.id,
    'release_transaction_id',release_tx.id,'status','cancelled',
    'returned_amount',w.amount
  );
 end $$;

revoke execute on function public.admin_cancel_withdrawal(uuid, uuid, text, text)
from public, anon, authenticated;
grant execute on function public.admin_cancel_withdrawal(uuid, uuid, text, text)
to service_role;

-- If the full schema was already installed, replace the signup trigger
-- function with this idempotent version. New accounts receive the configured
-- bonus once, in the same database transaction as their profile and wallet.
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path=public as $$
declare new_profile_id uuid := new.id;
declare wallet_id uuid;
declare welcome_reference text := 'WELCOME-' || upper(substr(replace(new_profile_id::text,'-',''),1,12));
declare welcome_transaction_id uuid;
declare configured_bonus public.bonus_settings%rowtype;
declare bonus_amount numeric(20,2);
declare bonus_currency text;
begin
  select * into configured_bonus from public.bonus_settings where id = true;
  bonus_amount := case when coalesce(configured_bonus.enabled,false) then coalesce(configured_bonus.amount,0) else 0 end;
  bonus_currency := coalesce(configured_bonus.currency,'ZMW');
  insert into public.profiles(id,first_name,last_name,display_name,username,phone,zedmoney_id)
  values (
    new_profile_id,
    coalesce(new.raw_user_meta_data->>'first_name',''),
    coalesce(new.raw_user_meta_data->>'last_name',''),
    nullif(trim(coalesce(new.raw_user_meta_data->>'first_name','') || ' ' || coalesce(new.raw_user_meta_data->>'last_name','')),''),
    nullif(lower(trim(new.raw_user_meta_data->>'username')),''),
    nullif(new.raw_user_meta_data->>'phone',''),
    public.new_zedmoney_id()
  )
  on conflict (id) do nothing;
  insert into public.wallets(user_id,wallet_identifier,currency,available_balance)
  values (new_profile_id,'ZW-' || upper(substr(replace(gen_random_uuid()::text,'-',''),1,12)),bonus_currency,bonus_amount)
  on conflict (user_id) do nothing;
  select id into wallet_id from public.wallets where user_id = new_profile_id;
  insert into public.wallet_limits(user_id) values (new_profile_id) on conflict (user_id) do nothing;
  if bonus_amount > 0 then
    insert into public.transactions(reference,user_id,wallet_id,type,status,amount,fee,net_amount,currency,description,metadata,completed_at)
    select welcome_reference,new_profile_id,wallet_id,'adjustment','successful',bonus_amount,0,bonus_amount,bonus_currency,
      'ZedMoney welcome bonus',jsonb_build_object('welcome_bonus',true,'amount',bonus_amount,'currency',bonus_currency),now()
    where not exists (select 1 from public.transactions t where t.reference=welcome_reference)
    returning id into welcome_transaction_id;
    if welcome_transaction_id is not null then
      insert into public.ledger_entries(wallet_id,transaction_id,entry_type,direction,amount,currency,balance_before,balance_after,reference,description,metadata)
      values (wallet_id,welcome_transaction_id,'welcome_bonus','credit',bonus_amount,bonus_currency,0,bonus_amount,welcome_reference,'ZedMoney welcome bonus',jsonb_build_object('welcome_bonus',true,'amount',bonus_amount,'currency',bonus_currency));
      insert into public.notifications(user_id,type,title,message,metadata)
      values (new_profile_id,'welcome_bonus','Welcome to ZedMoney','Your ' || bonus_currency || ' ' || to_char(bonus_amount,'FM999999990.00') || ' welcome bonus is ready. Add funds to keep building your wallet.',jsonb_build_object('welcome_bonus',true,'amount',bonus_amount,'currency',bonus_currency,'action','add_funds'));
    end if;
  end if;
  return new;
end $$;

create or replace function public.admin_deduct_signup_bonus(
  p_bonus_transaction_id uuid,
  p_admin_user_id uuid
) returns jsonb
language plpgsql security definer set search_path=public as $$
declare
  bonus_tx public.transactions%rowtype;
  existing_deduction public.transactions%rowtype;
  wallet public.wallets%rowtype;
  deduction_tx public.transactions%rowtype;
  before_available numeric;
  after_available numeric;
  deduction_reference text;
begin
  if not exists (select 1 from public.admin_users where user_id=p_admin_user_id and active=true) then
    raise exception 'Administrator authorization required';
  end if;
  select * into bonus_tx from public.transactions
  where id=p_bonus_transaction_id and type='adjustment' and metadata->>'welcome_bonus'='true' for update;
  if bonus_tx.id is null then raise exception 'Signup bonus transaction not found'; end if;
  select * into existing_deduction from public.transactions
  where metadata->>'signup_bonus_deduction_of'=bonus_tx.id::text limit 1;
  if existing_deduction.id is not null then
    return jsonb_build_object('already_deducted',true,'transaction_id',existing_deduction.id,'bonus_transaction_id',bonus_tx.id,'status',existing_deduction.status);
  end if;
  select * into wallet from public.wallets where id=bonus_tx.wallet_id for update;
  if wallet.id is null then raise exception 'Wallet not found'; end if;
  before_available := wallet.available_balance;
  if before_available < bonus_tx.amount then
    raise exception 'The wallet does not have enough available funds to deduct this bonus';
  end if;
  after_available := before_available-bonus_tx.amount;
  deduction_reference := 'BONUS-REV-' || upper(substr(replace(gen_random_uuid()::text,'-',''),1,12));
  insert into public.transactions(reference,user_id,wallet_id,type,status,amount,fee,net_amount,currency,description,metadata,completed_at)
  values (deduction_reference,bonus_tx.user_id,wallet.id,'adjustment','successful',bonus_tx.amount,0,bonus_tx.amount,wallet.currency,
    'Signup bonus deducted by administrator',
    jsonb_build_object('signup_bonus_deduction',true,'signup_bonus_deduction_of',bonus_tx.id,'amount',bonus_tx.amount,'currency',wallet.currency),now())
  returning * into deduction_tx;
  update public.wallets set available_balance=after_available,updated_at=now() where id=wallet.id;
  insert into public.ledger_entries(wallet_id,transaction_id,entry_type,direction,amount,currency,balance_before,balance_after,reference,description,metadata)
  values (wallet.id,deduction_tx.id,'signup_bonus_deduction','debit',bonus_tx.amount,wallet.currency,before_available,after_available,
    deduction_reference,'Signup bonus deducted by administrator',jsonb_build_object('signup_bonus_transaction_id',bonus_tx.id));
  insert into public.audit_logs(admin_user_id,action,target_type,target_id,reason,metadata)
  values (p_admin_user_id,'DEDUCT_SIGNUP_BONUS','user',bonus_tx.user_id,'Signup bonus deducted by administrator',
    jsonb_build_object('bonus_transaction_id',bonus_tx.id,'deduction_transaction_id',deduction_tx.id,'amount',bonus_tx.amount));
  insert into public.notifications(user_id,type,title,message,metadata)
  values (bonus_tx.user_id,'welcome_bonus_deducted','Signup bonus adjusted',
    'Your signup bonus was removed by an administrator adjustment.',
    jsonb_build_object('bonus_transaction_id',bonus_tx.id,'deduction_transaction_id',deduction_tx.id,'amount',bonus_tx.amount));
  return jsonb_build_object('already_deducted',false,'transaction_id',deduction_tx.id,'bonus_transaction_id',bonus_tx.id,'amount',bonus_tx.amount,'status','successful');
end $$;

-- IMPORTANT:
-- The existing full schema contains all tables/columns required by the current
-- Lipila server integration and the welcome bonus:
--   deposits.provider / provider_reference / idempotency_key
--   withdrawals.provider / provider_reference / idempotency_key
--   transactions.provider / provider_reference / metadata
--   provider_webhook_events with UNIQUE(provider,event_id)
--   payment_link_payments.provider / provider_reference
--   notifications
--   wallets.available_balance / pending_balance / reserved_balance
-- Therefore no duplicate tables or columns are included here.

# ZedMoney Supabase setup

## Authentication architecture

`auth.html` is the only customer authentication surface. It uses the public Supabase URL and anon key for sign-in, account creation, recovery email, and session restoration. `index.html` performs a session check before revealing the wallet and redirects unauthenticated visitors back to `auth.html`, preserving safe internal hash destinations such as `index.html#send`.

The browser never receives the service-role key. After Supabase creates a user, the `on_auth_user_created` trigger creates the profile, generates the `zedmoney_id` in PostgreSQL, creates a wallet with zero balances, and creates the default wallet limits row. Keep this SQL trigger installed before enabling registration.

The administrator flow is separate from customer authentication. `admin.html` sends the password to the Node API; the API verifies `ADMIN_PASSWORD_HASH` and issues an expiring HttpOnly cookie. Do not add the admin password, its hash, or `ADMIN_SESSION_SECRET` to any HTML file.

This guide provisions the database used by `server.js`. ZedMoney uses Supabase Auth for identity and PostgreSQL for the authoritative wallet, transaction, and immutable ledger state. Lipila is intentionally not called in this version; provider columns and webhook storage are ready for a later adapter.

## 1. Create the project and configure Auth

1. Create a Supabase project and record its project URL, anon key, and service-role key.
2. In **Authentication → Providers**, enable Email. Keep email confirmation enabled for production.
3. In **Authentication → URL Configuration**, add the frontend URL and the local URL used during development (for example `http://localhost:3000`).
4. Never put the service-role key in a browser, ZIP, git repository, or support message.

## 2. Environment variables

Create a local `.env` (never commit or distribute it):

```env
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_ANON_KEY=your-anon-key
SUPABASE_SERVICE_ROLE_KEY=your-service-role-key
PORT=3000
FRONTEND_ORIGIN=http://localhost:3000
NODE_ENV=development
```

`SUPABASE_ANON_KEY` is safe for the browser because Supabase RLS still applies. `SUPABASE_SERVICE_ROLE_KEY` is **SERVER ONLY** and is used by trusted Node operations. `PORT` is supplied by Render when deployed. `FRONTEND_ORIGIN` must be a specific allowed origin in production; do not use `*`.

After setting up the project, put only the URL and anon key in the two `zedmoney:supabase-*` meta tags in both `index.html` and `auth.html`. The API base URL must be identical in both pages. The supplied pages currently use `https://zeedmoney-server.onrender.com`; replace that value if the API is hosted somewhere else.

## 3. SQL schema

Run the following in Supabase SQL Editor. Amounts use `numeric`, never JavaScript floating point. Ledger rows are append-only through privileges and triggers.

```sql
create extension if not exists pgcrypto;

create type public.user_status as enum ('active','pending','suspended','restricted','closed');
create type public.wallet_status as enum ('active','frozen','restricted','closed');
create type public.transaction_status as enum ('pending','processing','successful','failed','reversed','cancelled');
create type public.transaction_type as enum ('deposit','withdrawal','transfer','payment','payment_link','refund','adjustment','reserve','release','airtime','bill','reversal');

create or replace function public.touch_updated_at() returns trigger language plpgsql as $$
begin new.updated_at = now(); return new; end $$;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  first_name text not null default '', last_name text not null default '',
  display_name text, username text unique, phone text, country text not null default 'ZM',
  currency text not null default 'ZMW' check (char_length(currency)=3),
  avatar_url text, zedmoney_id text not null unique,
  provider_customer_reference text, provider_account_reference text,
  provider_metadata jsonb not null default '{}',
  status public.user_status not null default 'active',
  verification_status text not null default 'unverified',
  created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);
alter table public.profiles add column if not exists username text;
create unique index if not exists profiles_username_unique on public.profiles(lower(username)) where username is not null;

create table if not exists public.wallets (
  id uuid primary key default gen_random_uuid(), user_id uuid not null unique references public.profiles(id) on delete cascade,
  wallet_identifier text not null unique, currency text not null default 'ZMW' check (char_length(currency)=3),
  status public.wallet_status not null default 'active',
  available_balance numeric(20,2) not null default 0 check (available_balance >= 0),
  pending_balance numeric(20,2) not null default 0 check (pending_balance >= 0),
  reserved_balance numeric(20,2) not null default 0 check (reserved_balance >= 0),
  created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);

create table if not exists public.wallet_limits (
  id uuid primary key default gen_random_uuid(), user_id uuid unique references public.profiles(id) on delete cascade,
  minimum_transaction numeric(20,2) not null default 1, maximum_transaction numeric(20,2) not null default 10000,
  daily_deposit numeric(20,2) not null default 25000, daily_withdrawal numeric(20,2) not null default 10000,
  daily_transfer numeric(20,2) not null default 10000, monthly_volume numeric(20,2) not null default 100000,
  created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);

create table if not exists public.transactions (
  id uuid primary key default gen_random_uuid(), reference text not null unique,
  user_id uuid not null references public.profiles(id), wallet_id uuid not null references public.wallets(id),
  type public.transaction_type not null, status public.transaction_status not null default 'pending',
  amount numeric(20,2) not null check (amount > 0), fee numeric(20,2) not null default 0 check (fee >= 0),
  net_amount numeric(20,2) not null, currency text not null default 'ZMW',
  description text, recipient_user_id uuid references public.profiles(id), payment_link_id uuid,
  provider text, provider_reference text, idempotency_key text, metadata jsonb not null default '{}',
  created_at timestamptz not null default now(), updated_at timestamptz not null default now(), completed_at timestamptz
);
create unique index if not exists transactions_user_idempotency on public.transactions(user_id,idempotency_key) where idempotency_key is not null;

create table if not exists public.ledger_entries (
  id uuid primary key default gen_random_uuid(), wallet_id uuid not null references public.wallets(id),
  transaction_id uuid not null references public.transactions(id), entry_type text not null,
  direction text not null check (direction in ('credit','debit')), amount numeric(20,2) not null check (amount > 0),
  currency text not null default 'ZMW', balance_before numeric(20,2) not null, balance_after numeric(20,2) not null,
  reference text not null, description text, metadata jsonb not null default '{}', created_at timestamptz not null default now()
);
create or replace function public.prevent_ledger_mutation() returns trigger language plpgsql as $$
begin raise exception 'Ledger entries are immutable'; end $$;
drop trigger if exists ledger_no_update on public.ledger_entries;
create trigger ledger_no_update before update or delete on public.ledger_entries for each row execute function public.prevent_ledger_mutation();

create table if not exists public.deposits (
  id uuid primary key default gen_random_uuid(), user_id uuid not null references public.profiles(id),
  amount numeric(20,2) not null check (amount > 0), currency text not null default 'ZMW',
  method text not null check (method in ('mobile_money','card','ussd','payment_link')),
  status text not null default 'pending' check (status in ('pending','processing','successful','failed','cancelled','reversed')),
  provider text, provider_reference text, description text, idempotency_key text,
  created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);
create table if not exists public.withdrawals (
  id uuid primary key default gen_random_uuid(), user_id uuid not null references public.profiles(id),
  amount numeric(20,2) not null check (amount > 0), currency text not null default 'ZMW',
  method text not null, destination text not null, status text not null default 'pending',
  provider text, provider_reference text, idempotency_key text, created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);
create table if not exists public.money_requests (
  id uuid primary key default gen_random_uuid(), requester_id uuid not null references public.profiles(id),
  payer_id uuid not null references public.profiles(id), amount numeric(20,2) not null check (amount > 0),
  currency text not null default 'ZMW', note text, status text not null default 'pending',
  expires_at timestamptz, created_at timestamptz not null default now(), updated_at timestamptz not null default now(),
  check (requester_id <> payer_id)
);
create table if not exists public.payment_links (
  id uuid primary key default gen_random_uuid(), owner_id uuid not null references public.profiles(id),
  code text not null unique default upper(encode(gen_random_bytes(5),'hex')),
  amount numeric(20,2) not null check (amount > 0), currency text not null default 'ZMW',
  description text not null, expires_at timestamptz, status text not null default 'active',
  view_count integer not null default 0, payment_count integer not null default 0,
  created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);
alter table public.transactions add constraint transactions_payment_link_fk foreign key (payment_link_id) references public.payment_links(id);
create table if not exists public.payment_link_payments (
  id uuid primary key default gen_random_uuid(), payment_link_id uuid not null references public.payment_links(id),
  transaction_id uuid references public.transactions(id), amount numeric(20,2) not null, status text not null default 'pending',
  provider text, provider_reference text, created_at timestamptz not null default now()
);
create table if not exists public.recipients (
  id uuid primary key default gen_random_uuid(), user_id uuid not null references public.profiles(id) on delete cascade,
  recipient_user_id uuid references public.profiles(id), label text not null, phone text, favorite boolean not null default false,
  created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);
create table if not exists public.notifications (
  id uuid primary key default gen_random_uuid(), user_id uuid not null references public.profiles(id) on delete cascade,
  type text not null, title text not null, message text not null, read_at timestamptz, metadata jsonb not null default '{}', created_at timestamptz not null default now()
);
create table if not exists public.security_events (
  id uuid primary key default gen_random_uuid(), user_id uuid not null references public.profiles(id) on delete cascade,
  type text not null, description text, device text, ip_address inet, metadata jsonb not null default '{}', created_at timestamptz not null default now()
);
create table if not exists public.device_sessions (
  id uuid primary key default gen_random_uuid(), user_id uuid not null references public.profiles(id) on delete cascade,
  device_name text, last_seen_at timestamptz not null default now(), revoked_at timestamptz, created_at timestamptz not null default now()
);
create table if not exists public.user_restrictions (
  id uuid primary key default gen_random_uuid(), user_id uuid not null references public.profiles(id) on delete cascade,
  restriction text not null, reason text, active boolean not null default true, created_at timestamptz not null default now()
);
create table if not exists public.admin_roles (id uuid primary key default gen_random_uuid(), name text not null unique, description text);
create table if not exists public.admin_users (id uuid primary key default gen_random_uuid(), user_id uuid not null unique references auth.users(id), role_id uuid references public.admin_roles(id), active boolean not null default true, created_at timestamptz not null default now());
create table if not exists public.admin_permissions (id uuid primary key default gen_random_uuid(), name text not null unique);
create table if not exists public.admin_role_permissions (role_id uuid references public.admin_roles(id) on delete cascade, permission_id uuid references public.admin_permissions(id) on delete cascade, primary key(role_id,permission_id));
create table if not exists public.audit_logs (
  id uuid primary key default gen_random_uuid(), admin_user_id uuid not null references public.admin_users(id),
  action text not null, target_type text, target_id uuid, reason text not null, note text,
  ip_address inet, user_agent text, metadata jsonb not null default '{}', created_at timestamptz not null default now()
);
create table if not exists public.reconciliation_records (
  id uuid primary key default gen_random_uuid(), provider text, provider_reference text, transaction_id uuid references public.transactions(id),
  internal_amount numeric(20,2), provider_amount numeric(20,2), status text not null default 'open', notes text, created_at timestamptz not null default now()
);
create table if not exists public.fee_configurations (id uuid primary key default gen_random_uuid(), name text not null unique, fixed_amount numeric(20,2) not null default 0, percentage numeric(8,4) not null default 0, active boolean not null default true, created_at timestamptz not null default now());
create table if not exists public.provider_webhook_events (
  id uuid primary key default gen_random_uuid(), provider text not null, event_id text not null, event_type text,
  transaction_id uuid references public.transactions(id), payload jsonb not null, signature text, received_at timestamptz not null default now(),
  processed_at timestamptz, processing_status text not null default 'received', retry_count integer not null default 0, unique(provider,event_id)
);
create table if not exists public.idempotency_records (
  id uuid primary key default gen_random_uuid(), user_id uuid references public.profiles(id), operation text not null, idempotency_key text not null,
  response jsonb, created_at timestamptz not null default now(), unique(user_id,operation,idempotency_key)
);

create index if not exists transactions_user_created on public.transactions(user_id,created_at desc);
create unique index if not exists deposits_user_idempotency_unique on public.deposits(user_id,idempotency_key) where idempotency_key is not null;
create unique index if not exists withdrawals_user_idempotency_unique on public.withdrawals(user_id,idempotency_key) where idempotency_key is not null;

create index if not exists ledger_wallet_created on public.ledger_entries(wallet_id,created_at desc);
create index if not exists deposits_user_status on public.deposits(user_id,status);
create index if not exists withdrawals_user_status on public.withdrawals(user_id,status);
create index if not exists notifications_user_created on public.notifications(user_id,created_at desc);
create index if not exists audit_created on public.audit_logs(created_at desc);

create or replace function public.new_zedmoney_id() returns text language plpgsql as $$
declare candidate text;
begin loop candidate := 'ZM-' || lpad((floor(random()*999999)+1)::int::text,6,'0'); exit when not exists(select 1 from public.profiles where zedmoney_id=candidate); end loop; return candidate; end $$;

create or replace function public.create_internal_transfer(p_sender_id uuid,p_recipient text,p_amount numeric,p_currency text,p_note text,p_idempotency_key text)
returns jsonb language plpgsql security definer set search_path=public as $$
declare sender_wallet wallets%rowtype; recipient_profile profiles%rowtype; recipient_wallet wallets%rowtype; tx transactions%rowtype;
begin
  select * into tx from transactions where user_id=p_sender_id and idempotency_key=p_idempotency_key limit 1;
  if tx.id is not null then return jsonb_build_object('transaction_id',tx.id,'replayed',true); end if;
  select * into recipient_profile from profiles where zedmoney_id=p_recipient or phone=p_recipient limit 1;
  if recipient_profile.id is null or recipient_profile.id=p_sender_id then raise exception 'Recipient is invalid'; end if;
  select * into sender_wallet from wallets where user_id=p_sender_id for update;
  select * into recipient_wallet from wallets where user_id=recipient_profile.id for update;
  if sender_wallet.status <> 'active' or recipient_wallet.status <> 'active' then raise exception 'Wallet is not active'; end if;
  if sender_wallet.available_balance < p_amount then raise exception 'Insufficient available balance'; end if;
  insert into transactions(reference,user_id,wallet_id,type,status,amount,net_amount,currency,description,recipient_user_id,idempotency_key,completed_at)
  values ('TX-'||upper(substr(replace(gen_random_uuid()::text,'-',''),1,12)),p_sender_id,sender_wallet.id,'transfer','successful',p_amount,p_amount,p_currency,p_note,recipient_profile.id,p_idempotency_key,now()) returning * into tx;
  update wallets set available_balance=available_balance-p_amount where id=sender_wallet.id;
  update wallets set available_balance=available_balance+p_amount where id=recipient_wallet.id;
  insert into ledger_entries(wallet_id,transaction_id,entry_type,direction,amount,currency,balance_before,balance_after,reference,description) values
    (sender_wallet.id,tx.id,'transfer','debit',p_amount,p_currency,sender_wallet.available_balance,sender_wallet.available_balance-p_amount,tx.reference,p_note),
    (recipient_wallet.id,tx.id,'transfer','credit',p_amount,p_currency,recipient_wallet.available_balance,recipient_wallet.available_balance+p_amount,tx.reference,p_note);
  return jsonb_build_object('transaction_id',tx.id,'reference',tx.reference,'status',tx.status);
end $$;

create or replace function public.accept_money_request(p_request_id uuid,p_payer_id uuid)
returns jsonb language plpgsql security definer set search_path=public as $$
declare r money_requests%rowtype; sender wallets%rowtype; receiver wallets%rowtype; tx transactions%rowtype;
begin
  select * into r from money_requests where id=p_request_id for update;
  if r.id is null then raise exception 'Request not found'; end if;
  if r.payer_id <> p_payer_id then raise exception 'Only the payer can accept this request'; end if;
  if r.status <> 'pending' then raise exception 'Request is no longer pending'; end if;
  if r.expires_at is not null and r.expires_at <= now() then update money_requests set status='expired',updated_at=now() where id=r.id; raise exception 'Request has expired'; end if;
  select * into sender from wallets where user_id=r.payer_id for update;
  select * into receiver from wallets where user_id=r.requester_id for update;
  if sender.status <> 'active' or receiver.status <> 'active' then raise exception 'Wallet is not active'; end if;
  if sender.currency <> r.currency or receiver.currency <> r.currency then raise exception 'Currency mismatch'; end if;
  if sender.available_balance < r.amount then raise exception 'Insufficient available balance'; end if;
  insert into transactions(reference,user_id,wallet_id,type,status,amount,net_amount,currency,description,recipient_user_id,completed_at)
  values ('TX-'||upper(substr(replace(gen_random_uuid()::text,'-',''),1,12)),r.payer_id,sender.id,'transfer','successful',r.amount,r.amount,r.currency,r.note,r.requester_id,now()) returning * into tx;
  update wallets set available_balance=available_balance-r.amount,updated_at=now() where id=sender.id;
  update wallets set available_balance=available_balance+r.amount,updated_at=now() where id=receiver.id;
  insert into ledger_entries(wallet_id,transaction_id,entry_type,direction,amount,currency,balance_before,balance_after,reference,description) values
    (sender.id,tx.id,'transfer','debit',r.amount,r.currency,sender.available_balance,sender.available_balance-r.amount,tx.reference,r.note),
    (receiver.id,tx.id,'transfer','credit',r.amount,r.currency,receiver.available_balance,receiver.available_balance+r.amount,tx.reference,r.note);
  update money_requests set status='accepted',updated_at=now() where id=r.id;
  insert into notifications(user_id,type,title,message,metadata) values
    (r.requester_id,'money_received','Money received','Your money request was accepted.',jsonb_build_object('request_id',r.id,'transaction_id',tx.id)),
    (r.payer_id,'request_paid','Request paid','You accepted a money request.',jsonb_build_object('request_id',r.id,'transaction_id',tx.id));
  return jsonb_build_object('request_id',r.id,'transaction_id',tx.id,'reference',tx.reference,'status','accepted');
end $$;

create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path=public as $$
declare new_profile_id uuid := new.id;
declare wallet_id uuid := gen_random_uuid();
begin
  insert into public.profiles(id,first_name,last_name,display_name,username,phone,zedmoney_id)
  values (
    new_profile_id,
    coalesce(new.raw_user_meta_data->>'first_name',''),
    coalesce(new.raw_user_meta_data->>'last_name',''),
    nullif(trim(coalesce(new.raw_user_meta_data->>'first_name','') || ' ' || coalesce(new.raw_user_meta_data->>'last_name','')),''),
    nullif(trim(new.raw_user_meta_data->>'username'),''),
    nullif(new.raw_user_meta_data->>'phone',''),
    public.new_zedmoney_id()
  );
  insert into public.wallets(id,user_id,wallet_identifier,available_balance)
  values (wallet_id,new_profile_id,'ZW-' || upper(substr(replace(wallet_id::text,'-',''),1,12)),5);
  insert into public.wallet_limits(user_id) values (new_profile_id);
  insert into public.transactions(reference,user_id,wallet_id,type,status,amount,fee,net_amount,currency,description,metadata,completed_at)
  values (
    'WELCOME-' || upper(substr(replace(new_profile_id::text,'-',''),1,12)),
    new_profile_id,wallet_id,'adjustment','successful',5,0,5,'ZMW',
    'ZedMoney welcome bonus',
    jsonb_build_object('welcome_bonus',true,'amount',5),
    now()
  );
  insert into public.ledger_entries(wallet_id,transaction_id,entry_type,direction,amount,currency,balance_before,balance_after,reference,description,metadata)
  select wallet_id,id,'welcome_bonus','credit',5,'ZMW',0,5,reference,
    'ZedMoney welcome bonus',jsonb_build_object('welcome_bonus',true)
  from public.transactions
  where reference = 'WELCOME-' || upper(substr(replace(new_profile_id::text,'-',''),1,12));
  insert into public.notifications(user_id,type,title,message,metadata)
  values (
    new_profile_id,'welcome_bonus','Welcome to ZedMoney',
    'Your K5 welcome bonus is ready. Add funds to keep building your wallet.',
    jsonb_build_object('welcome_bonus',true,'amount',5,'action','add_funds')
  );
  return new;
end $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
for each row execute function public.handle_new_user();

create or replace function public.initiate_withdrawal(
  p_user_id uuid,p_amount numeric,p_currency text,p_method text,p_destination text,p_idempotency_key text
) returns jsonb language plpgsql security definer set search_path=public as $$
declare w wallets%rowtype; tx transactions%rowtype; withdrawal_id uuid;
begin
  select * into tx from transactions where user_id=p_user_id and idempotency_key=p_idempotency_key limit 1;
  if tx.id is not null then return jsonb_build_object('transaction_id',tx.id,'replayed',true); end if;
  select * into w from wallets where user_id=p_user_id for update;
  if w.id is null then raise exception 'Wallet not found'; end if;
  if w.status <> 'active' then raise exception 'Wallet is not active'; end if;
  if w.available_balance < p_amount then raise exception 'Insufficient available balance'; end if;
  insert into transactions(reference,user_id,wallet_id,type,status,amount,net_amount,currency,description,idempotency_key)
  values ('WD-'||upper(substr(replace(gen_random_uuid()::text,'-',''),1,12)),p_user_id,w.id,'withdrawal','pending',p_amount,p_amount,p_currency,p_method||' withdrawal',p_idempotency_key)
  returning * into tx;
  insert into withdrawals(user_id,amount,currency,method,destination,status,idempotency_key)
  values (p_user_id,p_amount,p_currency,p_method,p_destination,'pending',p_idempotency_key) returning id into withdrawal_id;
  update wallets set available_balance=available_balance-p_amount,reserved_balance=reserved_balance+p_amount where id=w.id;
  insert into ledger_entries(wallet_id,transaction_id,entry_type,direction,amount,currency,balance_before,balance_after,reference,description)
  values (w.id,tx.id,'withdrawal_reserve','debit',p_amount,p_currency,w.available_balance,w.available_balance-p_amount,tx.reference,'Funds reserved for pending withdrawal');
  return jsonb_build_object('withdrawal_id',withdrawal_id,'transaction_id',tx.id,'reference',tx.reference,'status','pending');
end $$;

create or replace function public.get_wallet_analytics(p_user_id uuid,p_from timestamptz default null,p_to timestamptz default null)
returns jsonb language sql security definer set search_path=public as $$
  select jsonb_build_object(
    'total_received',coalesce(sum(case when amount > 0 and type in ('deposit','transfer','payment','refund','adjustment') and status='successful' then amount else 0 end),0),
    'total_sent',coalesce(sum(case when type in ('withdrawal','transfer','payment','airtime','bill') and status='successful' then amount else 0 end),0),
    'transaction_count',count(*),
    'pending_transactions',count(*) filter (where status in ('pending','processing')),
    'successful_transactions',count(*) filter (where status='successful'),
    'failed_transactions',count(*) filter (where status in ('failed','reversed','cancelled'))
  )
  from transactions
  where user_id=p_user_id
    and (p_from is null or created_at >= p_from)
    and (p_to is null or created_at <= p_to);
$$;

create or replace function public.admin_adjust_wallet(
  p_wallet_id uuid,p_type text,p_amount numeric,p_reason text,p_reference text,p_admin_user_id uuid
) returns jsonb language plpgsql security definer set search_path=public as $$
declare w wallets%rowtype; tx transactions%rowtype; before_available numeric; after_available numeric; before_reserved numeric; after_reserved numeric;
begin
  if not exists(select 1 from admin_users where user_id=p_admin_user_id and active=true) then raise exception 'Administrator authorization required'; end if;
  if p_amount <= 0 or p_reason is null or length(trim(p_reason)) < 3 or p_reference is null or length(trim(p_reference)) < 3 then raise exception 'Adjustment details are required'; end if;
  select * into w from wallets where id=p_wallet_id for update;
  if w.id is null then raise exception 'Wallet not found'; end if;
  before_available := w.available_balance; before_reserved := w.reserved_balance;
  after_available := w.available_balance; after_reserved := w.reserved_balance;
  if p_type='credit' then after_available := after_available+p_amount;
  elsif p_type='debit' then after_available := after_available-p_amount;
  elsif p_type='reserve' then after_available := after_available-p_amount; after_reserved := after_reserved+p_amount;
  elsif p_type='release' then after_available := after_available+p_amount; after_reserved := after_reserved-p_amount;
  else raise exception 'Unsupported adjustment type'; end if;
  if after_available < 0 or after_reserved < 0 then raise exception 'Adjustment exceeds wallet funds'; end if;
  insert into transactions(reference,user_id,wallet_id,type,status,amount,net_amount,currency,description,completed_at)
  values (p_reference,w.user_id,w.id,'adjustment','successful',p_amount,p_amount,w.currency,p_reason,now()) returning * into tx;
  update wallets set available_balance=after_available,reserved_balance=after_reserved where id=w.id;
  insert into ledger_entries(wallet_id,transaction_id,entry_type,direction,amount,currency,balance_before,balance_after,reference,description)
  values (w.id,tx.id,p_type,case when p_type in ('debit','reserve') then 'debit' else 'credit' end,p_amount,w.currency,
    case when p_type in ('reserve','release') then before_reserved else before_available end,
    case when p_type in ('reserve','release') then after_reserved else after_available end,p_reference,p_reason);
  insert into audit_logs(admin_user_id,action,target_type,target_id,reason,note,metadata)
  values (p_admin_user_id,'BALANCE_'||upper(p_type),'wallet',w.id,p_reason,p_reference,jsonb_build_object('transaction_id',tx.id,'amount',p_amount));
  return jsonb_build_object('transaction_id',tx.id,'wallet_id',w.id,'status','successful');
end $$;
```

For production, keep the `security definer` functions owned by a locked-down database role and expose only the minimum `EXECUTE` privileges needed by the API.

## 4. Row Level Security

Enable RLS on every user-facing table:

```sql
do $$ declare t text; begin
  foreach t in array array['profiles','wallets','wallet_limits','transactions','deposits','withdrawals','money_requests','payment_links','payment_link_payments','recipients','notifications','security_events','device_sessions','user_restrictions'] loop
    execute format('alter table public.%I enable row level security', t);
  end loop;
end $$;

create policy "own profile" on profiles for select using (id = auth.uid());
create policy "own wallet" on wallets for select using (user_id = auth.uid());
create policy "own transactions" on transactions for select using (user_id = auth.uid());
create policy "own deposits" on deposits for select using (user_id = auth.uid());
create policy "own withdrawals" on withdrawals for select using (user_id = auth.uid());
create policy "own recipients" on recipients for all using (user_id = auth.uid()) with check (user_id = auth.uid());
create policy "own notifications" on notifications for select using (user_id = auth.uid());
create policy "read own security" on security_events for select using (user_id = auth.uid());
create policy "read own sessions" on device_sessions for select using (user_id = auth.uid());
create policy "request participants" on money_requests for select using (requester_id = auth.uid() or payer_id = auth.uid());
create policy "own links" on payment_links for all using (owner_id = auth.uid()) with check (owner_id = auth.uid());
```

The service role bypasses RLS, so the API must still enforce ownership and admin checks. The browser never supplies a trusted `user_id`, wallet balance, role, status, or ledger entry.

## 4.1 Admin permission seed

Run this once after creating the admin tables. Permissions are enforced by the Node API; do not trust a role value sent by the browser.

```sql
insert into public.admin_permissions(name) values
('overview.read'),('users.read'),('users.suspend'),('users.restore'),('users.restrict'),
('wallets.read'),('wallets.freeze'),('wallets.unfreeze'),('transactions.read'),
('deposits.read'),('withdrawals.read'),('withdrawals.manage'),('requests.read'),('payment_links.read'),
('ledger.read'),('ledger.adjust'),('audit.read'),('risk.read'),('security.read'),
('sessions.read'),('notifications.read'),('reconciliation.read'),('webhooks.read'),('limits.read'),('fees.read'),
('permissions.read'),('provider.read'),('jobs.read')
on conflict(name) do nothing;

insert into public.admin_roles(name,description) values
('Super Admin','Full operational access'),
('Operations Admin','Operational wallet and user management'),
('Finance Admin','Ledger, reconciliation and adjustments'),
('Risk Admin','Restrictions, risk and security')
on conflict(name) do nothing;

insert into public.admin_role_permissions(role_id,permission_id)
select r.id,p.id from public.admin_roles r cross join public.admin_permissions p
where r.name='Super Admin'
on conflict do nothing;
```

## 5. API reference

All responses use `{ "success": true, "data": ... }` or `{ "success": false, "error": { "code", "message" } }`.

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/api/health` | Public | Safe liveness response |
| GET | `/api/me`, `/api/me/profile` | User | Current identity and profile |
| PATCH | `/api/me/profile` | User | Update safe profile fields |
| GET | `/api/wallet`, `/api/wallet/balance` | User | Authoritative wallet read |
| GET | `/api/transactions`, `/api/transactions/:id` | User | Own paginated transactions |
| POST/GET | `/api/transfers` | User | Atomic internal transfer history; POST requires `Idempotency-Key` |
| POST/GET | `/api/deposits`, `/api/deposits/:id` | User | Create/read pending external deposit records |
| POST/GET | `/api/withdrawals`, `/api/withdrawals/:id` | User | Reserve and read pending withdrawals |
| POST/GET | `/api/requests` | User | Create and list money requests |
| POST | `/api/requests/:id/accept`, `/decline`, `/cancel` | User | Update an owned or participating request |
| GET/POST | `/api/payment-links` | User | Create/list links; creation does not collect external funds |
| GET | `/api/payment-links/:id` | User | Read an owned link |
| POST | `/api/payment-links/:id/disable` | User | Disable an owned link |
| GET/POST/PATCH/DELETE | `/api/recipients` and `/:id` | User | Own saved recipients |
| GET | `/api/notifications` | User | Own notifications |
| POST | `/api/notifications/:id/read`, `/read-all` | User | Mark notifications read |
| GET | `/api/analytics`, `/api/statements` | User | Database-derived summaries and statement data |
| GET | `/api/security/events`, `/api/sessions` | User | Security and device records |
| GET | `/api/admin/overview` | Admin | Live operational counts |
| GET | `/api/admin/users`, `/users/:id` | Admin | User records and wallet summary |
| POST | `/api/admin/users/:id/suspend`, `/restore`, `/restrict` | Admin | Server-enforced account controls |
| GET | `/api/admin/wallets`, `/wallets/:id` | Admin | Wallet records |
| POST | `/api/admin/wallets/:id/freeze`, `/unfreeze` | Admin | Server-enforced wallet controls |
| GET | `/api/admin/transactions`, `/deposits`, `/withdrawals`, `/money_requests`, `/payment-links` | Admin | Financial operational records |
| POST | `/api/admin/withdrawals/:id/cancel` | Admin | Decline a pending withdrawal, return its reserved funds, and create an audited ledger release |
| GET | `/api/admin/ledger`, `/audit`, `/risk`, `/security-events`, `/sessions` | Admin | Ledger, audit and security views |
| GET | `/api/admin/reconciliation`, `/webhooks`, `/limits`, `/fees`, `/permissions` | Admin | Operational configuration and provider records |
| GET | `/api/admin/provider-status`, `/jobs` | Admin | Provider/job status; Lipila remains unconfigured |
| POST | `/api/admin/adjustments` | Admin | Atomic, reasoned, audited wallet adjustment |

Invalid input returns `VALIDATION_ERROR`; missing or invalid bearer tokens return `UNAUTHENTICATED`; ownership failures return `NOT_FOUND`; rejected financial operations return a safe business error such as `INSUFFICIENT_BALANCE`.

## 6. Local development and Render

Run `npm install` and then `npm start`. The server serves the configured frontend files at `/` and `/index.html`, the authentication page at `/auth.html`, and API routes under `/api/*`. Set `FRONTEND_DIR`, `INDEX_FILE`, and `AUTH_FILE` when the HTML files are not named `index.html` and `auth.html`. Render should use **Build Command** `npm install` and **Start Command** `npm start`; its `PORT` variable is read automatically. Use `.env.example` as the list of required environment settings, but never commit a real `.env` file.

The admin screen must remain inaccessible to protected API data until an authenticated identity is inserted into `admin_users`. Do not add an admin password to either HTML file. Create a role, permission rows, and an `admin_users` row in a controlled SQL migration or internal operations process.

## 7. Testing and financial controls

Before production, test health, signup, login, refresh/logout, protected-route rejection, ownership isolation, wallet creation, atomic transfer, insufficient funds, idempotent replay, pending deposit/withdrawal states, requests, links, notifications, statements, frozen/suspended restrictions, admin authorization, ledger immutability, and audit creation.

Deposits and withdrawals stay `pending` until a trusted provider integration confirms settlement. The frontend cannot credit balances or declare external success. The supplied Node API now provides the Lipila collection adapter, status checks, signed webhook handling, provider-reference persistence and idempotent database settlement; apply `supabase_lipila_additions_*.md` after this base schema before enabling those routes.
## Lipila server integration

The Node API now owns Lipila communication. The browser must never receive `LIPILA_API_KEY` or `LIPILA_WEBHOOK_SECRET`.

Set these server environment variables:

- `LIPILA_ENVIRONMENT=sandbox` for testing or `production` for live traffic.
- `LIPILA_BASE_URL=https://api.lipila.dev` for sandbox or `https://blz.lipila.io` for production.
- `LIPILA_API_KEY` to the merchant API key from Lipila.
- `LIPILA_WEBHOOK_SECRET` to the webhook signing secret configured in Lipila.
- `LIPILA_CALLBACK_URL=https://YOUR_DOMAIN/api/webhooks/lipila`.
- `WITHDRAWAL_DELAY_HOURS=24`.

The server uses the existing `deposits`, `withdrawals`, `transactions`, `wallets`, `ledger_entries`, `notifications`, and `provider_webhook_events` tables. No client-side balance mutation is permitted.

For Lipila production, configure the webhook URL to `/api/webhooks/lipila`. Lipila's published webhook security requires HMAC-SHA256 verification, a five-minute timestamp tolerance, and idempotent processing by webhook ID.

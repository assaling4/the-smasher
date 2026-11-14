-- =====================================================================
-- THE SMASHER - online backend (Supabase)
-- Paste this whole file into Supabase > SQL Editor > New query > Run.
-- It is safe to run again: it only creates what is missing and
-- replaces the functions.
--
-- How it works
--  * Every browser first signs in "anonymously" with Supabase (no email).
--  * Our own ID + password accounts live in the table below. Logging in
--    links ("binds") that anonymous browser to the account.
--  * Tables are locked (row level security, no policies). The game can
--    only use the functions in this file, so nobody can read passwords,
--    recovery codes or other players' friend lists.
-- =====================================================================

create extension if not exists pgcrypto with schema extensions;

create table if not exists public.accounts(
  id            uuid primary key default gen_random_uuid(),
  username      text not null,
  username_key  text not null unique,          -- lower-case copy, keeps IDs unique
  pw_hash       text,                          -- null for guests
  recovery_hash text,
  is_guest      boolean not null default false,
  fails         int not null default 0,
  locked_until  timestamptz,
  created_at    timestamptz not null default now()
);

create table if not exists public.bindings(     -- which browser is logged in to which account
  auth_uid   uuid primary key,
  account_id uuid not null references public.accounts(id) on delete cascade,
  bound_at   timestamptz not null default now()
);
create index if not exists bindings_account on public.bindings(account_id);

create table if not exists public.friendships(  -- one row per request / friendship
  from_id    uuid not null references public.accounts(id) on delete cascade,
  to_id      uuid not null references public.accounts(id) on delete cascade,
  accepted   boolean not null default false,
  created_at timestamptz not null default now(),
  primary key(from_id,to_id)
);
create index if not exists friendships_to on public.friendships(to_id);

alter table public.accounts    enable row level security;
alter table public.bindings    enable row level security;
alter table public.friendships enable row level security;
revoke all on public.accounts, public.bindings, public.friendships from anon, authenticated;

-- ---------------------------------------------------------------------
-- helpers
-- ---------------------------------------------------------------------
create or replace function public.sm_valid_name(n text) returns text
language plpgsql immutable set search_path = public as $$
declare bad text[] := array['fuck','shit','bitch','cunt','nigg','fag','dick','pussy','porn','sex','rape','hitler','nazi',
  '시발','씨발','ㅅㅂ','ㅆㅂ','병신','ㅂㅅ','개새','지랄','좆','존나','썅','니미','느금','애미','애비','섹스','보지','자지','미친놈','미친년'];
  w text; k text;
begin
  if n is null or char_length(n) < 1 then return 'empty'; end if;
  if char_length(n) > 10 then return 'long'; end if;
  -- letters must be English or Korean; numbers and symbols are fine; no spaces
  if n !~ '^[A-Za-z0-9가-힣ㄱ-ㅎㅏ-ㅣ!-/:-@\[-`{-~]+$' then return 'chars'; end if;
  k := lower(n);
  foreach w in array bad loop
    if position(w in k) > 0 then return 'bad'; end if;
  end loop;
  return null;
end $$;

create or replace function public.sm_me_id() returns uuid
language sql stable security definer set search_path = public as $$
  select account_id from bindings where auth_uid = auth.uid()
$$;

create or replace function public.sm_need_me() returns uuid
language plpgsql stable security definer set search_path = public as $$
declare a uuid;
begin
  if auth.uid() is null then raise exception 'no_session'; end if;
  a := sm_me_id();
  if a is null then raise exception 'not_logged_in'; end if;
  return a;
end $$;

create or replace function public.sm_account_json(a uuid) returns json
language sql stable security definer set search_path = public as $$
  select json_build_object('id',id,'name',username,'guest',is_guest) from accounts where id = a
$$;

-- drop a guest account that no browser uses any more (frees its nickname)
create or replace function public.sm_cleanup_guest(a uuid) returns void
language sql security definer set search_path = public as $$
  delete from accounts x where x.id = a and x.is_guest
    and not exists(select 1 from bindings b where b.account_id = a)
$$;

-- ---------------------------------------------------------------------
-- account functions (called by the game)
-- ---------------------------------------------------------------------
create or replace function public.sm_me() returns json
language sql stable security definer set search_path = public as $$
  select sm_account_json(sm_me_id())
$$;

create or replace function public.sm_sign_up(p_name text, p_pass text) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare e text; a uuid; old uuid; code text;
begin
  if auth.uid() is null then raise exception 'no_session'; end if;
  e := sm_valid_name(p_name); if e is not null then raise exception 'name_%', e; end if;
  if p_pass is null or char_length(p_pass) < 4 or char_length(p_pass) > 64 then raise exception 'pass_len'; end if;
  if exists(select 1 from accounts where username_key = lower(p_name)) then raise exception 'name_taken'; end if;
  code := upper(substr(encode(gen_random_bytes(6),'hex'),1,4) || '-' || substr(encode(gen_random_bytes(6),'hex'),1,4));
  insert into accounts(username,username_key,pw_hash,recovery_hash)
    values(p_name, lower(p_name), crypt(p_pass, gen_salt('bf',8)), crypt(code, gen_salt('bf',8)))
    returning id into a;
  old := sm_me_id();
  insert into bindings(auth_uid,account_id) values(auth.uid(),a)
    on conflict(auth_uid) do update set account_id = excluded.account_id, bound_at = now();
  if old is not null then perform sm_cleanup_guest(old); end if;
  return json_build_object('account',sm_account_json(a),'recovery',code);
exception when unique_violation then raise exception 'name_taken';
end $$;

create or replace function public.sm_log_in(p_name text, p_pass text) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare r accounts; old uuid;
begin
  if auth.uid() is null then raise exception 'no_session'; end if;
  select * into r from accounts where username_key = lower(p_name) and not is_guest;
  -- wrong logins return an error instead of raising, so the fail counter is saved
  if r.id is null then return json_build_object('error','wrong_login'); end if;
  if r.locked_until is not null and r.locked_until > now() then return json_build_object('error','locked'); end if;
  if r.pw_hash is null or r.pw_hash <> crypt(p_pass, r.pw_hash) then
    update accounts set fails = fails + 1,
      locked_until = case when fails + 1 >= 5 then now() + interval '1 minute' else locked_until end
      where id = r.id;
    return json_build_object('error','wrong_login');
  end if;
  update accounts set fails = 0, locked_until = null where id = r.id;
  old := sm_me_id();
  -- one device per account: log every other browser out of this account
  delete from bindings where account_id = r.id and auth_uid <> auth.uid();
  insert into bindings(auth_uid,account_id) values(auth.uid(),r.id)
    on conflict(auth_uid) do update set account_id = excluded.account_id, bound_at = now();
  if old is not null and old <> r.id then perform sm_cleanup_guest(old); end if;
  return sm_account_json(r.id);
end $$;

create or replace function public.sm_reset_password(p_name text, p_code text, p_pass text) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare r accounts;
begin
  select * into r from accounts where username_key = lower(p_name) and not is_guest;
  if r.id is null then return json_build_object('error','wrong_code'); end if;
  if r.locked_until is not null and r.locked_until > now() then return json_build_object('error','locked'); end if;
  if r.recovery_hash is null or r.recovery_hash <> crypt(upper(trim(p_code)), r.recovery_hash) then
    update accounts set fails = fails + 1,
      locked_until = case when fails + 1 >= 5 then now() + interval '1 minute' else locked_until end
      where id = r.id;
    return json_build_object('error','wrong_code');
  end if;
  if p_pass is null or char_length(p_pass) < 4 or char_length(p_pass) > 64 then raise exception 'pass_len'; end if;
  update accounts set pw_hash = crypt(p_pass, gen_salt('bf',8)), fails = 0, locked_until = null where id = r.id;
  delete from bindings where account_id = r.id;   -- log out everywhere
  return json_build_object('ok',true);
end $$;

create or replace function public.sm_guest_start(p_name text) returns json
language plpgsql security definer set search_path = public as $$
declare a uuid; e text;
begin
  if auth.uid() is null then raise exception 'no_session'; end if;
  a := sm_me_id();
  if a is not null then
    if exists(select 1 from accounts where id = a and is_guest) then return sm_account_json(a); end if;
    delete from bindings where auth_uid = auth.uid();   -- was logged in: become a guest on this browser
  end if;
  e := sm_valid_name(p_name); if e is not null then raise exception 'name_%', e; end if;
  if exists(select 1 from accounts where username_key = lower(p_name)) then raise exception 'name_taken'; end if;
  insert into accounts(username,username_key,is_guest) values(p_name,lower(p_name),true) returning id into a;
  insert into bindings(auth_uid,account_id) values(auth.uid(),a);
  return sm_account_json(a);
exception when unique_violation then raise exception 'name_taken';
end $$;

create or replace function public.sm_set_nickname(p_name text) returns json
language plpgsql security definer set search_path = public as $$
declare a uuid := sm_need_me(); e text;
begin
  if not exists(select 1 from accounts where id = a and is_guest) then raise exception 'not_guest'; end if;
  e := sm_valid_name(p_name); if e is not null then raise exception 'name_%', e; end if;
  if exists(select 1 from accounts where username_key = lower(p_name) and id <> a) then raise exception 'name_taken'; end if;
  update accounts set username = p_name, username_key = lower(p_name) where id = a;
  return sm_account_json(a);
exception when unique_violation then raise exception 'name_taken';
end $$;

create or replace function public.sm_log_out() returns void
language plpgsql security definer set search_path = public as $$
declare a uuid := sm_me_id();
begin
  delete from bindings where auth_uid = auth.uid();
  if a is not null then perform sm_cleanup_guest(a); end if;
end $$;

-- ---------------------------------------------------------------------
-- friends (max 20, requests must be accepted)
-- ---------------------------------------------------------------------
create or replace function public.sm_friend_count(a uuid) returns int
language sql stable security definer set search_path = public as $$
  select count(*)::int from friendships where accepted and (from_id = a or to_id = a)
$$;

create or replace function public.sm_find(p_name text) returns json
language plpgsql stable security definer set search_path = public as $$
declare a uuid := sm_need_me(); r accounts;
begin
  select * into r from accounts where username_key = lower(trim(p_name));
  if r.id is null then return null; end if;
  return json_build_object('id',r.id,'name',r.username,'guest',r.is_guest,'me',r.id = a,
    'status',(select case when f.accepted then 'friend' when f.from_id = a then 'sent' else 'incoming' end
              from friendships f where (f.from_id = a and f.to_id = r.id) or (f.from_id = r.id and f.to_id = a) limit 1));
end $$;

create or replace function public.sm_friend_request(p_id uuid) returns text
language plpgsql security definer set search_path = public as $$
declare a uuid := sm_need_me();
begin
  if p_id = a then raise exception 'self'; end if;
  if not exists(select 1 from accounts where id = p_id) then raise exception 'no_user'; end if;
  if exists(select 1 from friendships where accepted and ((from_id=a and to_id=p_id) or (from_id=p_id and to_id=a))) then return 'friend'; end if;
  if sm_friend_count(a) >= 20 then raise exception 'my_full'; end if;
  if sm_friend_count(p_id) >= 20 then raise exception 'their_full'; end if;
  -- they already asked me: just accept
  if exists(select 1 from friendships where from_id = p_id and to_id = a) then
    update friendships set accepted = true where from_id = p_id and to_id = a;
    return 'friend';
  end if;
  if (select count(*) from friendships where from_id = a and not accepted) >= 30 then raise exception 'too_many'; end if;
  insert into friendships(from_id,to_id) values(a,p_id) on conflict do nothing;
  return 'sent';
end $$;

create or replace function public.sm_friend_answer(p_id uuid, p_accept boolean) returns text
language plpgsql security definer set search_path = public as $$
declare a uuid := sm_need_me();
begin
  if not exists(select 1 from friendships where from_id = p_id and to_id = a and not accepted) then raise exception 'no_request'; end if;
  if not p_accept then delete from friendships where from_id = p_id and to_id = a; return 'declined'; end if;
  if sm_friend_count(a) >= 20 then raise exception 'my_full'; end if;
  if sm_friend_count(p_id) >= 20 then raise exception 'their_full'; end if;
  update friendships set accepted = true where from_id = p_id and to_id = a;
  return 'friend';
end $$;

create or replace function public.sm_friend_remove(p_id uuid) returns void
language plpgsql security definer set search_path = public as $$
declare a uuid := sm_need_me();
begin
  delete from friendships where (from_id = a and to_id = p_id) or (from_id = p_id and to_id = a);
end $$;

create or replace function public.sm_friends() returns json
language plpgsql stable security definer set search_path = public as $$
declare a uuid := sm_need_me();
begin
  return coalesce((select json_agg(json_build_object('id',x.id,'name',x.username,'guest',x.is_guest,
      'status',case when f.accepted then 'friend' when f.from_id = a then 'sent' else 'incoming' end) order by lower(x.username))
    from friendships f join accounts x on x.id = case when f.from_id = a then f.to_id else f.from_id end
    where f.from_id = a or f.to_id = a), '[]'::json);
end $$;

-- only these functions may be called from the game
revoke execute on function public.sm_valid_name(text), public.sm_me_id(), public.sm_need_me(),
  public.sm_account_json(uuid), public.sm_cleanup_guest(uuid), public.sm_friend_count(uuid) from public, anon, authenticated;
revoke execute on function public.sm_me(), public.sm_sign_up(text,text), public.sm_log_in(text,text),
  public.sm_reset_password(text,text,text), public.sm_guest_start(text), public.sm_set_nickname(text),
  public.sm_log_out(), public.sm_find(text), public.sm_friend_request(uuid), public.sm_friend_answer(uuid,boolean),
  public.sm_friend_remove(uuid), public.sm_friends() from public, anon;
grant execute on function public.sm_me(), public.sm_sign_up(text,text), public.sm_log_in(text,text),
  public.sm_reset_password(text,text,text), public.sm_guest_start(text), public.sm_set_nickname(text),
  public.sm_log_out(), public.sm_find(text), public.sm_friend_request(uuid), public.sm_friend_answer(uuid,boolean),
  public.sm_friend_remove(uuid), public.sm_friends() to authenticated;

create schema if not exists private;
revoke all on schema private from public, anon, authenticated;
grant usage on schema private to authenticated;

create table public.organizations (
    id uuid primary key default gen_random_uuid(),
    name text not null check (length(trim(name)) > 0),
    created_at timestamptz not null default now()
);

create table public.profiles (
    id uuid primary key references auth.users (id) on delete cascade,
    display_name text not null default '',
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create table public.organization_memberships (
    organization_id uuid not null references public.organizations (id) on delete cascade,
    user_id uuid not null references auth.users (id) on delete cascade,
    role text not null check (role in ('org_admin', 'analyst', 'viewer')),
    created_at timestamptz not null default now(),
    primary key (organization_id, user_id)
);

create table public.platform_admins (
    user_id uuid primary key references auth.users (id) on delete cascade,
    added_at timestamptz not null default now(),
    added_by uuid references auth.users (id) on delete set null
);

create table public.alerts (
    id uuid primary key default gen_random_uuid(),
    organization_id uuid not null references public.organizations (id) on delete cascade,
    source_event_id text,
    title text not null,
    severity text not null check (severity in ('low', 'medium', 'high', 'critical')),
    status text not null default 'open' check (status in ('open', 'acknowledged', 'resolved')),
    source_payload jsonb not null default '{}'::jsonb,
    ai_review jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    unique (organization_id, source_event_id)
);

create table public.vulnerability_findings (
    id uuid primary key default gen_random_uuid(),
    organization_id uuid not null references public.organizations (id) on delete cascade,
    asset text not null,
    title text not null,
    cve_id text,
    severity text not null check (severity in ('low', 'medium', 'high', 'critical')),
    status text not null default 'open' check (status in ('open', 'acknowledged', 'resolved')),
    details jsonb not null default '{}'::jsonb,
    first_seen_at timestamptz not null default now(),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create table public.audit_logs (
    id uuid primary key default gen_random_uuid(),
    organization_id uuid references public.organizations (id) on delete set null,
    actor_id uuid references auth.users (id) on delete set null,
    action text not null,
    entity_type text not null,
    entity_id text,
    details jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default now()
);

create index organization_memberships_user_id_idx
    on public.organization_memberships (user_id);
create index alerts_organization_created_at_idx
    on public.alerts (organization_id, created_at desc);
create index vulnerability_findings_organization_created_at_idx
    on public.vulnerability_findings (organization_id, created_at desc);
create index audit_logs_organization_created_at_idx
    on public.audit_logs (organization_id, created_at desc);

create function private.is_platform_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
    select exists (
        select 1
        from public.platform_admins
        where user_id = (select auth.uid())
    );
$$;

create function private.is_organization_member(target_organization_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
    select exists (
        select 1
        from public.organization_memberships
        where organization_id = target_organization_id
          and user_id = (select auth.uid())
    );
$$;

create function private.has_organization_role(
    target_organization_id uuid,
    allowed_roles text[]
)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
    select exists (
        select 1
        from public.organization_memberships
        where organization_id = target_organization_id
          and user_id = (select auth.uid())
          and role = any (allowed_roles)
    );
$$;

create function public.current_user_is_platform_admin()
returns boolean
language sql
stable
security invoker
set search_path = ''
as $$
    select private.is_platform_admin();
$$;

grant execute on function private.is_platform_admin() to authenticated;
grant execute on function private.is_organization_member(uuid) to authenticated;
grant execute on function private.has_organization_role(uuid, text[]) to authenticated;
grant execute on function public.current_user_is_platform_admin() to authenticated;
revoke execute on function public.current_user_is_platform_admin() from public, anon;

create function private.set_updated_at()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
    new.updated_at = now();
    return new;
end;
$$;

create trigger profiles_set_updated_at
before update on public.profiles
for each row execute function private.set_updated_at();

create trigger alerts_set_updated_at
before update on public.alerts
for each row execute function private.set_updated_at();

create trigger vulnerability_findings_set_updated_at
before update on public.vulnerability_findings
for each row execute function private.set_updated_at();

create function private.create_profile_for_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
    insert into public.profiles (id, display_name)
    values (
        new.id,
        coalesce(
            nullif(new.raw_user_meta_data ->> 'display_name', ''),
            nullif(new.email, ''),
            'User'
        )
    );
    return new;
end;
$$;

create trigger on_auth_user_created
after insert on auth.users
for each row execute function private.create_profile_for_new_user();

alter table public.organizations enable row level security;
alter table public.profiles enable row level security;
alter table public.organization_memberships enable row level security;
alter table public.platform_admins enable row level security;
alter table public.alerts enable row level security;
alter table public.vulnerability_findings enable row level security;
alter table public.audit_logs enable row level security;

create policy "Members and platform admins can read organizations"
on public.organizations for select to authenticated
using (
    private.is_platform_admin()
    or private.is_organization_member(id)
);

create policy "Users can read their own profile and platform admins can read all"
on public.profiles for select to authenticated
using (
    id = (select auth.uid())
    or private.is_platform_admin()
);

create policy "Users can update their own profile"
on public.profiles for update to authenticated
using (id = (select auth.uid()))
with check (id = (select auth.uid()));

create policy "Users can read memberships in their organizations"
on public.organization_memberships for select to authenticated
using (
    user_id = (select auth.uid())
    or private.is_platform_admin()
    or private.has_organization_role(organization_id, array['org_admin'])
);

create policy "Organization members and platform admins can read alerts"
on public.alerts for select to authenticated
using (
    private.is_platform_admin()
    or private.is_organization_member(organization_id)
);

create policy "Analysts and organization admins can create alerts"
on public.alerts for insert to authenticated
with check (
    private.is_platform_admin()
    or private.has_organization_role(organization_id, array['org_admin', 'analyst'])
);

create policy "Analysts and organization admins can update alerts"
on public.alerts for update to authenticated
using (
    private.is_platform_admin()
    or private.has_organization_role(organization_id, array['org_admin', 'analyst'])
)
with check (
    private.is_platform_admin()
    or private.has_organization_role(organization_id, array['org_admin', 'analyst'])
);

create policy "Organization admins can delete alerts"
on public.alerts for delete to authenticated
using (
    private.is_platform_admin()
    or private.has_organization_role(organization_id, array['org_admin'])
);

create policy "Organization members and platform admins can read findings"
on public.vulnerability_findings for select to authenticated
using (
    private.is_platform_admin()
    or private.is_organization_member(organization_id)
);

create policy "Analysts and organization admins can create findings"
on public.vulnerability_findings for insert to authenticated
with check (
    private.is_platform_admin()
    or private.has_organization_role(organization_id, array['org_admin', 'analyst'])
);

create policy "Analysts and organization admins can update findings"
on public.vulnerability_findings for update to authenticated
using (
    private.is_platform_admin()
    or private.has_organization_role(organization_id, array['org_admin', 'analyst'])
)
with check (
    private.is_platform_admin()
    or private.has_organization_role(organization_id, array['org_admin', 'analyst'])
);

create policy "Organization admins can delete findings"
on public.vulnerability_findings for delete to authenticated
using (
    private.is_platform_admin()
    or private.has_organization_role(organization_id, array['org_admin'])
);

create policy "Organization members and platform admins can read audit logs"
on public.audit_logs for select to authenticated
using (
    private.is_platform_admin()
    or (
        organization_id is not null
        and private.is_organization_member(organization_id)
    )
);

grant all on public.organizations to service_role;
grant all on public.profiles to service_role;
grant all on public.organization_memberships to service_role;
grant all on public.platform_admins to service_role;
grant all on public.alerts to service_role;
grant all on public.vulnerability_findings to service_role;
revoke all on public.organizations from public, anon, authenticated;
revoke all on public.profiles from public, anon, authenticated;
revoke all on public.organization_memberships from public, anon, authenticated;
revoke all on public.platform_admins from public, anon, authenticated;
revoke all on public.alerts from public, anon, authenticated;
revoke all on public.vulnerability_findings from public, anon, authenticated;
revoke all on public.audit_logs from public, anon, authenticated;

grant select on public.organizations to authenticated;
grant select, update on public.profiles to authenticated;
grant select on public.organization_memberships to authenticated;
grant select, insert, update, delete on public.alerts to authenticated;
grant select, insert, update, delete on public.vulnerability_findings to authenticated;
grant select on public.audit_logs to authenticated;

grant all on public.organizations to service_role;
grant all on public.profiles to service_role;
grant all on public.organization_memberships to service_role;
grant all on public.platform_admins to service_role;
grant all on public.alerts to service_role;
grant all on public.vulnerability_findings to service_role;
grant all on public.audit_logs to service_role;

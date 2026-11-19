create table public.scan_targets (
    id uuid primary key default gen_random_uuid(),
    organization_id uuid not null references public.organizations (id) on delete cascade,
    url text not null,
    hostname text not null,
    verification_token text not null default replace(gen_random_uuid()::text, '-', ''),
    verified_at timestamptz,
    created_by uuid default auth.uid() references auth.users (id) on delete set null,
    created_at timestamptz not null default now(),
    unique (organization_id, hostname)
);

create table public.scans (
    id uuid primary key default gen_random_uuid(),
    organization_id uuid not null references public.organizations (id) on delete cascade,
    target_id uuid not null references public.scan_targets (id) on delete cascade,
    status text not null default 'queued'
        check (status in ('queued', 'running', 'completed', 'failed')),
    requested_by uuid default auth.uid() references auth.users (id) on delete set null,
    findings_count integer,
    error text,
    created_at timestamptz not null default now(),
    started_at timestamptz,
    finished_at timestamptz
);

create index scans_organization_created_idx on public.scans (organization_id, created_at desc);
create index scans_target_idx on public.scans (target_id);

alter table public.scan_targets enable row level security;
alter table public.scans enable row level security;

revoke all on public.scan_targets, public.scans from public, anon, authenticated;
grant select, delete on public.scan_targets to authenticated;
grant insert (organization_id, url, hostname) on public.scan_targets to authenticated;
grant select on public.scans to authenticated;
grant insert (organization_id, target_id) on public.scans to authenticated;
grant all on public.scan_targets, public.scans to service_role;

create policy "Members and platform admins can read scan targets"
on public.scan_targets for select to authenticated
using (
    private.is_platform_admin()
    or private.is_organization_member(organization_id)
);

create policy "Organization admins can add scan targets"
on public.scan_targets for insert to authenticated
with check (
    private.is_platform_admin()
    or private.has_organization_role(organization_id, array['org_admin'])
);

create policy "Organization admins can remove scan targets"
on public.scan_targets for delete to authenticated
using (
    private.is_platform_admin()
    or private.has_organization_role(organization_id, array['org_admin'])
);

create policy "Members and platform admins can read scans"
on public.scans for select to authenticated
using (
    private.is_platform_admin()
    or private.is_organization_member(organization_id)
);

create policy "Organization admins can scan verified targets"
on public.scans for insert to authenticated
with check (
    (
        private.is_platform_admin()
        or private.has_organization_role(organization_id, array['org_admin'])
    )
    and exists (
        select 1
        from public.scan_targets target
        where target.id = target_id
            and target.organization_id = scans.organization_id
            and target.verified_at is not null
    )
);

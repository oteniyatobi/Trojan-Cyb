create or replace function public.create_organization(p_name text)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
    requesting_user_id uuid := (select auth.uid());
    organization_name text := trim(coalesce(p_name, ''));
    existing_organization_id uuid;
    new_organization_id uuid;
begin
    if requesting_user_id is null then
        raise exception 'Authentication is required'
            using errcode = '42501';
    end if;

    if organization_name = '' or length(organization_name) > 120 then
        raise exception 'Organization name must contain 1 to 120 characters'
            using errcode = '22023';
    end if;

    perform 1
    from auth.users
    where id = requesting_user_id
    for update;

    select organization_id
    into existing_organization_id
    from public.organization_memberships
    where user_id = requesting_user_id
    order by created_at
    limit 1;

    if existing_organization_id is not null then
        return existing_organization_id;
    end if;

    insert into public.organizations (name)
    values (organization_name)
    returning id into new_organization_id;

    insert into public.organization_memberships (organization_id, user_id, role)
    values (new_organization_id, requesting_user_id, 'org_admin');

    return new_organization_id;
end;
$$;

revoke all on function public.create_organization(text)
from public, anon;
grant execute on function public.create_organization(text)
to authenticated;

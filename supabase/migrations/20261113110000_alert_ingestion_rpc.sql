create or replace function public.ingest_alert(
    p_organization_id uuid,
    p_source_event_id text,
    p_title text,
    p_severity text,
    p_source_payload jsonb,
    p_ai_review jsonb
)
returns table (alert_id uuid, inserted boolean)
language plpgsql
security definer
set search_path = ''
as $$
declare
    inserted_id uuid;
begin
    insert into public.alerts (
        organization_id,
        source_event_id,
        title,
        severity,
        source_payload,
        ai_review
    )
    values (
        p_organization_id,
        p_source_event_id,
        p_title,
        p_severity,
        p_source_payload,
        p_ai_review
    )
    on conflict (organization_id, source_event_id) do nothing
    returning id into inserted_id;

    if inserted_id is not null then
        return query select inserted_id, true;
    elsif p_source_event_id is not null then
        return query
        select alerts.id, false
        from public.alerts
        where alerts.organization_id = p_organization_id
          and alerts.source_event_id = p_source_event_id;
    end if;
end;
$$;

revoke all on function public.ingest_alert(uuid, text, text, text, jsonb, jsonb)
from public, anon, authenticated;
grant execute on function public.ingest_alert(uuid, text, text, text, jsonb, jsonb)
to service_role;

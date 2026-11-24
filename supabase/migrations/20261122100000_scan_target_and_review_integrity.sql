-- Two integrity fixes found in review.
--
-- 1. scan_targets: hostname must be the host of url.
--    Org admins can insert scan_targets directly through Supabase, not
--    only through the backend. Nuclei and Wapiti scan `url`, but Nmap
--    scans `hostname`. With the two different, someone could confirm a
--    site they own and get Nmap pointed at someone else's host. (If
--    ownership verification comes back, it also reads `url`.)
--    url must also be a bare http(s) origin with a public-looking
--    domain name (no IP address, no .local/.internal/.localhost), as the
--    backend's normalize_url produces.
--    NOT VALID: checks new and changed rows only. The backend also
--    re-checks every target before verifying or scanning it.
--
-- 2. alerts and vulnerability_findings: signed-in users may change only
--    `status`. The AI review, severity, title and the source data are
--    written by the backend (service_role) and are no longer editable from
--    the dashboard, so an analyst can't rewrite what the AI said.

alter table public.scan_targets
    drop constraint if exists scan_targets_url_matches_hostname;
alter table public.scan_targets
    add constraint scan_targets_url_matches_hostname check (
        -- labels of letters, digits and hyphens; the last label starts with
        -- a letter, so an IP address like 169.254.169.254 doesn't match
        url ~ '^https?://([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]([a-z0-9-]*[a-z0-9])?(:[0-9]{1,5})?$'
        and hostname = substring(url from '^https?://([^/:]+)')
        and hostname !~ '\.(local|internal|localhost)$'
    ) not valid;

revoke update on public.alerts from authenticated;
grant update (status) on public.alerts to authenticated;

revoke update on public.vulnerability_findings from authenticated;
grant update (status) on public.vulnerability_findings to authenticated;

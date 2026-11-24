-- Private bucket for raw scanner output (Nmap XML, Nuclei JSONL, Wapiti
-- JSON), gzipped. Findings link to it in details.raw_output_ref as
-- "scan-raw-output/<organization_id>/<scan_id>/<file>.gz".
--
-- Not public and no policies: only the backend (service_role) reads or
-- writes it. Raw output names the customer's website and its weaknesses,
-- which is why it isn't kept as a GitHub artifact on the public repository.

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('scan-raw-output', 'scan-raw-output', false, 5242880, array['application/gzip'])
on conflict (id) do nothing;

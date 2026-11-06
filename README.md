# verdifax, R SDK and Reproducible-Research Toolkit

R client for the Verdifax cryptographic attestation pipeline. Designed
for researchers who want to attest computational results with the same
cryptographic rigor financial-services and AI governance customers
receive.

## Install

From a local clone (typical during early development):

```r
remotes::install_local("path/to/verdifax-sdk-r")
```

From GitHub (once published):

```r
remotes::install_github("Verdifax/verdifax-sdk-r")
```

## Usage

```r
library(verdifax)

# 1. Construct a client (reads VERDIFAX_BASE_URL, then VERDIFAX_API_URL,
#    and VERDIFAX_API_KEY from environment; defaults to
#    https://api.verdifax.com and a 90-second request timeout)
client <- verdifax_client()

# 2. Auto-capture the current R research environment
ctx <- verdifax_capture_environment(
  declared_seeds = list(rng = 42, torch = 1337)
)
# ctx is a list with: runtime_name="R", runtime_version="4.x.x",
# pinned_dependencies=c(...), git_commit_sha="...", platform="...",
# random_seeds=c("rng=42", "torch=1337"), declared=TRUE

# 3. Attest a result with the environment fingerprint bound in
result <- verdifax_attest(
  client = client,
  payload = "my-analysis-output",
  program_id = strrep("0", 64),
  route_id = "paper-figure-3",
  registry_record_hash = strrep("0", 64),
  reproducibility_context = ctx
)
cat("manifest_hash:", result$manifest$ManifestHash, "\n")

# 4. Verify two replays produce the same manifest hash
det <- verdifax_verify_determinism(
  client = client,
  payload = "my-analysis-output",
  program_id = strrep("0", 64),
  route_id = "paper-figure-3-verify",
  registry_record_hash = strrep("0", 64),
  reproducibility_context = ctx
)
stopifnot(det$deterministic)
```

## Versioning

From 1.0, a breaking change needs a new major version.

## Settings

| Setting | `verdifax_client()` argument | Environment variable | Default |
|---------|------------------------------|----------------------|---------|
| Base URL | `base_url` | `VERDIFAX_BASE_URL`, then `VERDIFAX_API_URL` | `https://api.verdifax.com` |
| API key | `api_key` | `VERDIFAX_API_KEY` | none |
| Timeout | `timeout`, in seconds | `VERDIFAX_TIMEOUT_MS` | 90 seconds |
| User agent | `user_agent` | `VERDIFAX_USER_AGENT` | `verdifax-r/<version>` |
| Retries | `max_retries` | `VERDIFAX_MAX_RETRIES` | 3 |
| First retry delay | `retry_base_delay`, in seconds | none | 0.2 seconds |

`verdifax_client()` reads the base URL and API key from the environment. `verdifax_from_env()` also reads the timeout, user agent and retry variables.

GET, HEAD and OPTIONS requests are retried after a network failure or an HTTP 429, 502, 503 or 504, with exponential backoff and full jitter. POST is never retried.

## Functions

| Function | Endpoint |
|----------|----------|
| `verdifax_health()` | `GET /health` |
| `verdifax_version()` | `GET /version` |
| `verdifax_get_openapi()` | `GET /openapi.json` |
| `verdifax_get_stats()` | `GET /stats` |
| `verdifax_attest()` | `POST /execute` |
| `verdifax_execute()` | `POST /execute` |
| `verdifax_job_step()` | `POST /execute` |
| `verdifax_attest_claude_response()` | `POST /execute` |
| `verdifax_attest_openai_response()` | `POST /execute` |
| `verdifax_execute_batch()` | `POST /execute/batch` |
| `verdifax_verify_determinism()` | `POST /execute/verify-determinism` |
| `verdifax_get_run()` | `GET /runs/{id}` |
| `verdifax_verify_run()` | `GET /runs/{id}/verify` |
| `verdifax_list_runs()` | `GET /runs` |
| `verdifax_search_runs()` | `GET /runs/search` |
| `verdifax_export_runs()` | `GET /runs/export` |
| `verdifax_export_runs_csv()` | `GET /runs/export?format=csv` |
| `verdifax_get_run_artifacts()` | `GET /runs/{id}/artifacts` |
| `verdifax_get_run_report()` | `GET /runs/{id}/report` |
| `verdifax_download_audit_pdf()` | `GET /runs/{id}/report.pdf` |
| `verdifax_get_allow_token()` | `GET /runs/{id}/allow-token` |
| `verdifax_get_deny_receipt()` | `GET /runs/{id}/deny-receipt` |
| `verdifax_get_ccv_halt_receipt()` | `GET /runs/{id}/ccv-halt-receipt` |
| `verdifax_get_macc_halt_receipt()` | `GET /runs/{id}/macc-halt-receipt` |
| `verdifax_get_aivp_t4_halt_receipt()` | `GET /runs/{id}/aivp-t4-halt-receipt` |
| `verdifax_get_attestation_gap_receipt()` | `GET /runs/{id}/attestation-gap-receipt` |
| `verdifax_get_ces_audit_record()` | `GET /runs/{id}/ces-audit-record` |
| `verdifax_list_deletion_receipts()` | `GET /runs/{id}/deletion-receipts` |
| `verdifax_list_attestations()` | `GET /attestations` |
| `verdifax_get_attestation()` | `GET /attestations/{id}` |
| `verdifax_get_public_bundle()` | `GET /runs/{id}/bundle.json` |
| `verdifax_get_public_bundle_by_token()` | `GET /public/runs/{token}/bundle.json` |
| `verdifax_dcae_verify()` | `POST /dcae/verify` |
| `verdifax_register_request_key()` | `POST /keys/request-key` |
| `verdifax_rotate_request_key()` | `POST /keys/request-key` |
| `verdifax_clear_request_key()` | `DELETE /keys/request-key` |
| `verdifax_admin_create_key()` | `POST /admin/keys` |
| `verdifax_admin_list_keys()` | `GET /admin/keys` |
| `verdifax_admin_revoke_key()` | `DELETE /admin/keys/{id}` |
| `verdifax_admin_clear_request_key()` | `DELETE /admin/keys/{id}/request-key` |
| `verdifax_admin_erase()` | `POST /admin/erase` |

These make no request: `verdifax_client()`, `verdifax_from_env()`, `verdifax_job()`, `verdifax_capture_environment()`, `verdifax_format_provider_payload()`, `verdifax_sign_request()`, `verdifax_request_key_registration_body()`, `verdifax_request_signature_preimage()`, `verdifax_generate_request_key()`, `verdifax_validate_hex64()`, `verdifax_validate_route_id()`, `verdifax_dse_dispatch_hash()`, `verdifax_dcae_closure_hash()`, `verdifax_cres_receipt_hash()` and `verdifax_run_statuses()`.

`verdifax_get_run_artifacts()`, `verdifax_get_public_bundle()` and `verdifax_get_public_bundle_by_token()` return the exact JSON text the server sent, so you can save it and check it with `verdifax-verify`.

## Runs

```r
page <- verdifax_list_runs(client, limit = 50, offset = 0)
one <- verdifax_get_run(client, page$runs[[1]]$id)
found <- verdifax_search_runs(client, status = "ok", from = "2026-11-01T00:00:00Z")

check <- verdifax_verify_run(client, result$run_id)
```

`verdifax_verify_run()` asks the server to recompute the manifest hash from the run's stored fields. `check$verified` is `TRUE` when it matches the recorded hash. It does not re-run the pipeline, and it is a check performed by Verdifax. For an independent offline check of the sealed audit bundle, use the open-source [`verdifax-verify`](https://github.com/Verdifax/verdifax-verify) CLI.

## Batch runs

`verdifax_execute_batch()` sends up to 1,000 runs in one request and stops with an error for more, before sending anything. Each row is a list with the argument names of `verdifax_attest()`. A row that fails comes back in `results` with `ok` set to `FALSE`, so the call does not stop for it.

```r
batch <- verdifax_execute_batch(client, list(
  list(payload = "first", program_id = strrep("0", 64), route_id = "paper",
       registry_record_hash = strrep("0", 64)),
  list(payload = "second", program_id = strrep("0", 64), route_id = "paper",
       registry_record_hash = strrep("0", 64))
))

for (row in batch$results) {
  cat(row$index, row$ok, row$error, "\n")
}
```

The client's `timeout` covers the whole batch, so raise it for a large one. A batch is one POST and it is never retried. After a timeout the server may have run some or all of the rows, so list your runs before you send them again.

## Jobs

A job is a map of the steps of one piece of work. Each step names the records it directly follows, so work can split into branches and join again. This example runs one step, two after it, and a final step joining them:

```r
job <- verdifax_job(client, "loan-1")

step <- function(step_id, payload, ...) {
  verdifax_job_step(
    job, step_id, ...,
    payload = payload,
    program_id = strrep("0", 64),
    route_id = "loan",
    registry_record_hash = strrep("0", 64)
  )
}

step("intake", "application received")
step("credit", "credit check", after = "intake")
step("fraud", "fraud check", after = "intake")
step("decide", "approved", after = c("credit", "fraud"), final = TRUE)

job$record_hashes # step id to record hash
```

Without `after`, a step follows the step run just before it through this job, and the first step follows nothing. `after = character(0)` or `after = list()` starts another root step. A step id the job has not recorded is refused before anything is sent. `external_previous` names records from outside the job.

A refused or halted step stays in the map. `verdifax_job_step()` records its hash and then stops with the same error as `verdifax_attest()`, so a later step can name it in `after`. A step that sealed nothing, such as a timeout or a 409, is not recorded and does not change which step comes next. A successful step with no `record_hash` uses its manifest hash, and if the response holds neither, the call stops with an error, so the map never silently gets a gap.

`job_id` and `step_id` are 1 to 128 letters, digits, dots, underscores, colons or dashes, and anything else is refused before sending. To build the block yourself, pass `job` to `verdifax_attest()`, `verdifax_execute()` or a provider helper, or put it in a batch row. The hash lists are sorted and repeats removed for you. A block with an unknown field, a `final` that is not `TRUE` or `FALSE`, or hash lists that are not vectors or lists of strings is refused before sending. `verdifax_export_runs()` and `verdifax_export_runs_csv()` take `job_id` to export one job's runs.

A job map covers what was sent. It cannot show a step that was never sent.

## Evidence export

`verdifax_export_runs()` lists the runs the server holds for your key in a period, failures included, with up to 10,000 rows per export. `verdifax_export_runs_csv()` returns the same rows as raw CSV text.

```r
evidence <- verdifax_export_runs(
  client, from = "2026-11-01T00:00:00Z", to = "2026-12-01T00:00:00Z"
)
evidence$total
evidence$truncated

export <- verdifax_export_runs_csv(
  client, from = "2026-11-01T00:00:00Z", to = "2026-12-01T00:00:00Z"
)
if (export$truncated) {
  warning("The CSV holds part of ", export$total, " runs. Use a narrower period.")
}
export$csv
```

The export states what the server stored, not a verdict. A call that never reached Verdifax cannot appear in it. Both forms say when a period holds more rows than the export returned: check `truncated`. `verdifax_export_runs_csv()` reads `total` and `truncated` from the `X-Verdifax-Total` and `X-Verdifax-Truncated` response headers, and stops with an error if the server does not send them. In the CSV, a `route_id` that a spreadsheet could read as a formula gets a leading `'`.

## Provider helpers

`verdifax_attest_claude_response()` and `verdifax_attest_openai_response()` attest a prompt and response as one payload: canonical JSON, exactly `{"prompt":...,"provider":...,"response":...}` with sorted keys and no extra whitespace, UTF-8, with `provider` set to `anthropic` or `openai`. `verdifax_format_provider_payload()` builds that text. All four Verdifax SDKs produce the same bytes.

Both take an optional `job` block and return what `verdifax_attest()` returns, including `record_hash` and `signed_request`, and their errors hold both too. `govern` is `FALSE` by default. Set `govern = TRUE` to also send the response text as `ai_output_text` for the AIVP review, which runs on Anthropic in production. Without it, the AI output text is not sent for review.

## Optional execute fields

`verdifax_attest()`, `verdifax_execute()`, `verdifax_execute_batch()` and `verdifax_verify_determinism()` accept `attested_context`, `reproducibility_context`, `request_substance`, `authorization_chain`, `regulatory_scaffolding` and `causal_graph`. Each is recorded as supplied and Verdifax does not check it. Write a JSON array as an unnamed list, so that one item stays an array. The client derives `attested` and `declared` from the fields you provide. Leave out `request_substance$origin$source_ip_hash` and `user_agent_hash`: the server computes them. `verdifax_attest()`, `verdifax_execute()` and `verdifax_verify_determinism()` refuse them before sending, and a batch row that sets them fails in `results`.

These functions check that `program_id` and `registry_record_hash` are 64 lowercase hex characters and that `route_id` is 1 to 256 printable ASCII characters.

## What `verdifax_capture_environment()` records

| Field                  | Source                                    |
|------------------------|-------------------------------------------|
| `runtime_name`         | hardcoded `"R"`                           |
| `runtime_version`      | `R.version$major.minor`                   |
| `pinned_dependencies`  | `installed.packages()` (name + version)   |
| `git_commit_sha`       | `git rev-parse HEAD` (best-effort)        |
| `random_seeds`         | caller-supplied list, sorted              |
| `platform`             | GOOS/GOARCH from `Sys.info()`             |
| `container_image_hash` | `/proc/self/cgroup` on Linux (best-effort)|

All fields are optional. Auto-detection failures silently leave the
field `NULL`; the orchestrator records `NULL` as "not declared"
rather than fabricating an environment claim.

## What the determinism check answers

`verdifax_verify_determinism()` runs your payload through the
pipeline twice and reports whether both invocations produced
byte-identical canonical manifest hashes. The `deterministic` flag
is grounded on **manifest hash** equality, the seal of the pipeline
output. Bundle hash differences (when surfaced in
`diff$differing_fields`) indicate server-observed timing variation
and are labeled `(informational)`. Both runs are recorded, with the
status `probe`.

## Request signing

Request signing is optional. A client with no signing key sends the same requests as before.

You can register an Ed25519 public key on your API key, so that each run must also be signed with a private key that only you hold. The key pair is created on your machine, and Verdifax receives only the public key. Signing needs the `sodium` package:

```r
install.packages("sodium")
```

```r
# Run once, then store private_key as a secret. It is 32 raw bytes.
keys <- verdifax_generate_request_key()

client <- verdifax_client(signing_key = keys$private_key)
verdifax_register_request_key(client) # sends the public key with its proof

# verdifax_attest(), verdifax_execute_batch() and
# verdifax_verify_determinism() now sign.
result <- verdifax_attest(
  client = client,
  payload = "my-analysis-output",
  program_id = strrep("0", 64),
  route_id = "paper-figure-3",
  registry_record_hash = strrep("0", 64)
)

# Replace the key. The current key approves, then the client signs with the new one.
new_key <- verdifax_generate_request_key()$private_key
verdifax_rotate_request_key(client, new_key)

# The current key approves. This stops requiring signatures on this API key,
# and the client then sends unsigned requests.
verdifax_clear_request_key(client)
```

Registering a key changes that API key for every client that uses it: the server then refuses a run without a valid signature, so every caller on the key needs the private key. Each request carries the time and a fresh random nonce. The server refuses a repeated nonce and a time more than five minutes from its own clock.

A signed call serializes the request once and signs those exact bytes with signature version 2, which also covers the AI output and the job block. The request goes as `signed_request`, a JSON string, beside `request_signature`, and the server reads only that text. The result holds `signed_request`, so you can save it and check it with `verdifax-verify --request FILE`. A refused or halted run stops with the httr2 error, and that condition holds `signed_request` and `record_hash`. In a batch each result holds its row's `signed_request`, and a job keeps each step's text in `job$signed_requests`, refused steps included. `verdifax_execute()` returns only the manifest, so use `verdifax_attest()` when you need the text. Its errors hold both fields. `verdifax_sign_request()` and `verdifax_request_signature_preimage()` still build the older version 1 signature, which cannot carry a job.

Once a key is registered, the server needs that key to approve replacing or clearing it. `verdifax_rotate_request_key()` and `verdifax_clear_request_key()` send that approval, so call them with a client that holds the current key. After a rotate the client and its copies sign with the new key. After a clear they drop the key and send unsigned requests, because the server refuses a signed run on an API key with no registered key. If the key is lost, an admin can clear it with `verdifax_admin_clear_request_key()` after a manual check.

In a batch each row carries its own signature and nonce, and the server checks them as it reaches that row. A row refused for its signature comes back in `results`, so a repeated batch returns HTTP 200 with failed rows, and a row reached more than five minutes after it was signed fails the same way. A determinism check uses one signature for the request, and repeating it returns HTTP 403.

A signature shows who requested the run, not that they accepted the outcome.

## Dependencies

- `httr2 (>= 1.1.0)`, HTTP client
- `jsonlite (>= 1.8.0)`, JSON serialization
- `openssl`, SHA-256 for the canonical hash functions
- `sodium`, optional, needed only for request signing

All are available on CRAN.

## License

MIT, see `LICENSE`.

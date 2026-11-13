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

On a trial key, register a request key first and give the client that key: see [Request signing](#request-signing). Without it, a trial key refuses the run.

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
| `verdifax_list_runs()` | `GET /runs`. A value the server cannot read stops with HTTP 400 unless `lenient = TRUE`; `verdifax_search_runs()`, `verdifax_list_account_runs()` and `verdifax_list_attestations()` take `lenient` too |
| `verdifax_search_runs()` | `GET /runs/search` |
| `verdifax_export_runs()` | `GET /runs/export` |
| `verdifax_export_runs_csv()` | `GET /runs/export?format=csv` |
| `verdifax_get_run_artifacts()` | `GET /runs/{id}/artifacts` |
| `verdifax_get_run_report()` | `GET /runs/{id}/report` |
| `verdifax_download_audit_pdf()` | `GET /runs/{id}/report.pdf`, or `POST` with `ai_output_text`, printed when its SHA-256 is the sealed hash. An unknown `format` is refused (HTTP 400) unless `fallback = "comprehensive"` |
| `verdifax_download_public_audit_pdf()` | `GET` or `POST /public/runs/{token}/report.pdf`, no key; takes `fallback` too |
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
| `verdifax_get_public_signoff()` | `GET /runs/{id}/signoff.json`: the sign-off a published run's audit report prints, and its job's decision in force |
| `verdifax_get_public_signoff_by_token()` | `GET /public/runs/{token}/signoff.json` |
| `verdifax_dcae_verify()` | `POST /dcae/verify` |
| `verdifax_register_request_key()` | `POST /keys/request-key` |
| `verdifax_rotate_request_key()` | `POST /keys/request-key` |
| `verdifax_clear_request_key()` | `DELETE /keys/request-key` |
| `verdifax_upload_policy()` | `POST /policies` |
| `verdifax_list_policies()` | `GET /policies` |
| `verdifax_get_policy()` | `GET /policies/{document_hash}` |
| `verdifax_test_policy()` | `POST /policies/test` |
| `verdifax_get_policy_history()` | `GET /policies/history` |
| `verdifax_activate_policy()` | `GET /policies`, then `POST /policies/{document_hash}/activate` |
| `verdifax_get_account()` | `GET /account` |
| `verdifax_set_account_setting()` | `GET /account` unless `account_id` is given, then `PUT /account/settings/{setting}`, signed by the owner's request key |
| `verdifax_delete_run()` | `GET /account` unless `account_id` is given, then `POST /account/runs/{id}/delete`, signed by the owner's request key |
| `verdifax_create_account_key()` | `POST /account/keys` |
| `verdifax_list_account_keys()` | `GET /account/keys` |
| `verdifax_revoke_account_key()` | `DELETE /account/keys/{id}` |
| `verdifax_register_account_request_key()` | `POST /account/request-key` |
| `verdifax_rotate_account_request_key()` | `POST /account/request-key`, with the current key's approval |
| `verdifax_clear_account_request_key()` | `DELETE /account/request-key` |
| `verdifax_list_account_runs()` | `GET /account/runs` |
| `verdifax_export_account_runs()` | `GET /account/runs/export` |
| `verdifax_export_account_runs_csv()` | `GET /account/runs/export?format=csv` |
| `verdifax_upload_account_policy()` | `POST /account/policies` |
| `verdifax_list_account_policies()` | `GET /account/policies` |
| `verdifax_get_account_policy()` | `GET /account/policies/{document_hash}` |
| `verdifax_test_account_policy()` | `POST /account/policies/test` |
| `verdifax_get_account_policy_history()` | `GET /account/policies/history` |
| `verdifax_activate_account_policy()` | `GET /account/policies`, then `POST /account/policies/{document_hash}/activate` |
| `verdifax_register_approver()` | `POST /account/approvers` |
| `verdifax_list_approvers()` | `GET /account/approvers` |
| `verdifax_revoke_approver()` | `DELETE /account/approvers/{id}` |
| `verdifax_get_newest_signoff()` | `GET /signoffs/newest`, or `GET /account/signoffs/newest` with `as_owner = TRUE` |
| `verdifax_sign_off()` | `GET /signoffs/newest`, then `POST /signoffs`; with `as_owner = TRUE`, `GET /account/signoffs/newest`, then `POST /account/signoffs` |
| `verdifax_get_signoffs()` | `GET /runs/{id}/signoffs`, or `GET /account/runs/{id}/signoffs` with `as_owner = TRUE` |
| `verdifax_get_signoff_history()` | `GET /account/signoffs/history` |
| `verdifax_get_signals()` | `GET /signals`, or `GET /account/signals` with `as_owner = TRUE` |
| `verdifax_follow_signals()` | `GET /signals` page after page, or `GET /account/signals` with `as_owner = TRUE` |
| `verdifax_create_feed_key()` | `POST /account/feed-keys` |
| `verdifax_revoke_feed_key()` | `DELETE /account/feed-keys/{id}` |
| `verdifax_create_webhook()` | `POST /account/webhooks` |
| `verdifax_list_webhooks()` | `GET /account/webhooks` |
| `verdifax_delete_webhook()` | `DELETE /account/webhooks/{id}` |
| `verdifax_list_webhook_deliveries()` | `GET /account/webhooks/{id}/deliveries` |
| `verdifax_get_failure_receipt()` | `GET /runs/{id}/failure-receipt` |
| `verdifax_admin_create_key()` | `POST /admin/keys` |
| `verdifax_admin_list_keys()` | `GET /admin/keys` |
| `verdifax_admin_revoke_key()` | `DELETE /admin/keys/{id}` |
| `verdifax_admin_clear_request_key()` | `DELETE /admin/keys/{id}/request-key` |
| `verdifax_admin_erase()` | `POST /admin/erase` |
| `verdifax_admin_create_account()` | `POST /admin/accounts` |
| `verdifax_admin_list_accounts()` | `GET /admin/accounts` |
| `verdifax_admin_replace_owner_key()` | `POST /admin/accounts/{id}/owner-key/replace` |
| `verdifax_admin_delete_run()` | `POST /admin/runs/{id}/delete` |

These make no request: `verdifax_client()`, `verdifax_from_env()`, `verdifax_job()`, `verdifax_capture_environment()`, `verdifax_format_provider_payload()`, `verdifax_sign_request()`, `verdifax_request_key_registration_body()`, `verdifax_request_signature_preimage()`, `verdifax_policy_activation_preimage()`, `verdifax_policy_activation_approval()`, `verdifax_owner_change_preimage()`, `verdifax_signoff_preimage()`, `verdifax_approver_key_proof()`, `verdifax_verify_webhook()`, `verdifax_signal_event_hash()`, `verdifax_generate_request_key()`, `verdifax_validate_hex64()`, `verdifax_validate_route_id()`, `verdifax_dse_dispatch_hash()`, `verdifax_dcae_closure_hash()`, `verdifax_cres_receipt_hash()` and `verdifax_run_statuses()`.

`verdifax_get_run_artifacts()`, `verdifax_get_public_bundle()`, `verdifax_get_public_bundle_by_token()`, `verdifax_get_policy_history()`, `verdifax_get_account_policy_history()`, `verdifax_get_signoffs()`, `verdifax_get_signoff_history()` and `verdifax_get_failure_receipt()` return the exact JSON text the server sent, so you can save it and check it with `verdifax-verify`.

## Runs

```r
page <- verdifax_list_runs(client, limit = 50, offset = 0)
one <- verdifax_get_run(client, page$runs[[1]]$id)
found <- verdifax_search_runs(client, status = "ok", from = "2026-11-01T00:00:00Z")

check <- verdifax_verify_run(client, result$run_id)
```

`verdifax_verify_run()` asks the server to recompute the manifest hash from the run's stored fields. `check$verified` is `TRUE` when it matches the recorded hash. It does not re-run the pipeline, and it is a check performed by Verdifax. For an independent offline check of the sealed audit bundle, use the open-source [`verdifax-verify`](https://github.com/Verdifax/verdifax-verify) CLI.

## Batch runs

`verdifax_execute_batch()` sends up to 1,000 runs in one request and stops with an error for more, before sending anything. Each row is a list with the argument names of `verdifax_attest()`. A row that fails comes back in `results` with `ok` set to `FALSE`, so the call does not stop for it. A name the server does not know, in a row or in its `attested_context`, stops the call before anything is sent, because the server refuses the whole batch with HTTP 400, naming it.

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

## Policies

A policy is a document you write: rules that decide whether a run on your API key goes ahead. Upload its exact text, try it on sample inputs, then activate it. Until you activate one, the built-in policy applies.

```r
path <- "loan-policy.json"
document <- readChar(path, file.size(path), useBytes = TRUE)

stored <- verdifax_upload_policy(client, document)
stored$document_hash # SHA-256 of the exact text

# Which rule would fire on sample inputs. This seals nothing.
trial <- verdifax_test_policy(
  client,
  inputs = list(
    subject_id = "u-17", subject_type = "user", verb = "approve",
    object_type = "transaction", classification = "CONFIDENTIAL"
  ),
  document_hash = stored$document_hash
)
trial$outcome
trial$fired_rule_id

# Make it the policy in force. With a signing_key, the client's request key
# signs the change.
change <- verdifax_activate_policy(client, stored$document_hash)

# A run that declares what the rules read. The server refuses it if another
# policy is active.
result <- verdifax_attest(
  client = client,
  payload = "loan 42 approved",
  program_id = strrep("0", 64),
  route_id = "loan-decision",
  registry_record_hash = strrep("0", 64),
  attested_context = list(actor_id = "u-17", actor_role = "loan_officer"),
  policy_context = list(
    actor_type = "user",
    mfa_satisfied = TRUE,
    session_age_seconds = 120,
    object_type = "transaction",
    object_id = "loan-42",
    classification = "CONFIDENTIAL"
  ),
  expected_policy_hash = stored$policy_hash
)

# Roll back by activating an earlier document. It is one more change in the
# chain, so the change it undoes stays on the record.
earlier <- verdifax_list_policies(client)$policies[[2]] # newest first
verdifax_activate_policy(client, earlier$document_hash)

# Save the chain of changes and check it offline.
writeLines(verdifax_get_policy_history(client), "policy-history.json", sep = "")
# verdifax-verify --policy-history policy-history.json
```

Verdifax did not write, review or approve your policy. A pass means the rules ran, not that they are good rules.

The document is sent as the exact string you give, because the server hashes its exact bytes. A list or any other object is refused before sending, since serializing it would change the hash. Read a file whole, as above: `readLines()` drops the final newline. `verdifax_get_policy()` returns the stored text, and `verdifax_list_policies()` lists your documents with `chain_id`, `newest_activation_hash` and `active_document_hash`.

`verdifax_activate_policy()` reads `GET /policies` for the chain and its newest change, then asks for the change naming that newest change. Once a request key is registered, the server needs that key to approve a change, so call it with a client that holds the key. An HTTP 409 means the change could not be made as asked, for example because someone changed the policy first or the document is not yet effective: the call stops with the server's message and is not retried. `verdifax_policy_activation_approval()` and `verdifax_policy_activation_preimage()` build the approval and its bytes without sending anything.

`policy_context` is what a run declares for the rules to read: `actor_type`, `mfa_satisfied`, `session_age_seconds`, `object_type`, `object_id`, `classification` and `data_quality`, all optional. `verdifax_attest()`, `verdifax_execute()`, `verdifax_verify_determinism()`, `verdifax_job_step()`, the provider helpers and each batch row accept it. An unknown field or a value outside the listed ones is refused before sending, so a misspelt field is never dropped. `actor_type`, `mfa_satisfied` and `session_age_seconds` describe the attested actor, so a set `actor_type`, `mfa_satisfied = TRUE` or a non-zero `session_age_seconds` needs an `attested_context` with at least one field set, such as `actor_id`, and is refused before sending otherwise. `mfa_satisfied = FALSE` and `session_age_seconds = 0` need none. The provider helpers send an `attested_context` with `actor_role` and `model_provider`, so they can carry any `policy_context` field. `expected_policy_hash` makes the server refuse the run with HTTP 409 when another policy is active. Both go inside `signed_request` on a signed client.

`data_quality` is your declaration about the data the decision used: a named list of `source` (at most 200 bytes), `as_of` (a time such as `"2026-11-11T09:00:00Z"` or `"2026-11-11T09:00:00+05:30"`) and `checks`, an unnamed list of up to 50 checks, each `list(name = , result = )` with a distinct name of at most 100 bytes and a result of `"pass"`, `"fail"` or `"warn"`. It needs no attested actor. It is sealed with the other values, a policy's `data_quality` condition can require and test it, and Verdifax judges none of it. A declaration the server would refuse is refused before sending.

A policy judges what you declared. It cannot show the declared facts are true.

A refusal stops the action only if your system waits for the answer.

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

The export states what the server stored, not a verdict. A call that never reached Verdifax cannot appear in it. Both forms say when a period holds more rows than the export returned: check `truncated`. `verdifax_export_runs_csv()` reads `total` and `truncated` from the `X-Verdifax-Total` and `X-Verdifax-Truncated` response headers, and stops with an error if the server does not send them. In the CSV, a `route_id` that a spreadsheet could read as a formula gets a leading `'`. Each row, in both forms, holds `api_key_id`, the id of the key that requested the run; in the CSV it is the last column, after `step_id`. Each run that `verdifax_list_runs()` and `verdifax_list_account_runs()` return holds it too.

## Accounts

An account is a company on Verdifax. Every API key belongs to one account for life. An account has an owner key, which manages the account, and member keys, which run. An admin creates the account and its first owner key, and the owner creates the member keys.

```r
# An admin creates the account and its owner key. VERDIFAX_API_KEY holds an
# admin key here.
admin <- verdifax_client()
created <- verdifax_admin_create_account(admin, "Acme Lending", tier = "trial")
created$account$account_id # for example "account-7"
created$owner_key$secret   # shown once: store it as a secret

# The owner key's request key signs every change to the account's policy.
request_key <- verdifax_generate_request_key()
owner <- verdifax_client(
  api_key = created$owner_key$secret,
  signing_key = request_key$private_key
)
verdifax_register_account_request_key(owner)
# Later, the owner replaces it: the current key approves the new one.
# verdifax_rotate_account_request_key(owner, verdifax_generate_request_key()$private_key)

# The owner creates the member keys that run.
member <- verdifax_create_account_key(owner, "loan-decisions")
member$secret # shown once: store it as a secret
verdifax_list_account_keys(owner)$keys

# The owner loads the account's policy, tries it, then activates it.
path <- "company-policy.json"
stored <- verdifax_upload_account_policy(owner, readChar(path, file.size(path), useBytes = TRUE))
verdifax_test_account_policy(
  owner,
  inputs = list(subject_id = "u-17", verb = "approve"),
  document_hash = stored$document_hash
)
verdifax_activate_account_policy(owner, stored$document_hash)

# The owner exports the runs of every key in the account.
evidence <- verdifax_export_account_runs(
  owner, from = "2026-11-01T00:00:00Z", to = "2026-12-01T00:00:00Z"
)
evidence$account_id
evidence$truncated
```

The account number is a label Verdifax assigned, not a verified company identity.

An account policy is your own: Verdifax did not write, review or approve it. Every key in the account must pass the account policy on top of its own policy, and a run is admitted only when both allow.

The account's view covers the runs its keys made through Verdifax, not runs made elsewhere.

An owner key cannot run anything. The server refuses it with HTTP 403 on the routes that run or read runs, so use member keys for runs and the owner key with the account functions above.

Every change to the account's policy must be signed by the owner key's request key, over the account's chain, for example `account-7`. `verdifax_activate_account_policy()` reads that chain and its newest change from `verdifax_list_account_policies()` and signs as `verdifax_activate_policy()` does. A client without a `signing_key` is refused before anything is sent, because the server refuses an unsigned change. `verdifax_rotate_account_request_key()` replaces the owner key's request key, approved by the current one, and the client switches to the new key only once the server accepts; a refusal, such as HTTP 409 when another change to that key came first, leaves the current key in place. Rolling back is activating an earlier document, and `verdifax_get_account_policy_history()` returns the chain of changes for `verdifax-verify --policy-history`.

`verdifax_export_account_runs()` and `verdifax_export_account_runs_csv()` take the same period and `job_id` as `verdifax_export_runs()`. The JSON export also holds `account_id`, `signoffs`, the account's whole chain of sign-offs, and, once the account has policy documents, `account_policy_documents` and `account_policy_history`. `verdifax_list_account_runs()` pages through the same runs with `limit` and `offset`. Every row and run holds `api_key_id`, so you can tell which of the account's keys requested it.

`verdifax_revoke_account_key()` revokes a member key. A key in another account, or an owner key, answers HTTP 404. A member key on a trial account needs its own request key before it seals anything, as every trial key does: see Request signing. An admin can also put a new key in an existing account with `verdifax_admin_create_key(admin, name, account_id = created$account$id)`. `verdifax_admin_list_accounts()` lists every account with its key counts.

### Settings and deletions the owner decides

The owner decides two settings, each `"allowed"` or `"blocked"`, which `verdifax_get_account()` returns as `owner_replacement` and `verdifax_deletion`. While `owner-replacement` is blocked, Verdifax cannot replace the account's owner key; while `verdifax-deletion` is blocked, Verdifax cannot delete the account's records. The owner can also delete one of the account's records itself.

```r
# The owner blocks both changes Verdifax could make. Each is signed by the
# owner's request key, sealed and placed in the feed as account.changed.
verdifax_set_account_setting(owner, "owner-replacement", "blocked")
verdifax_set_account_setting(owner, "verdifax-deletion", "blocked")

# The owner deletes one record, named by its record hash. A tombstone is
# sealed in its place and placed in the feed as run.deleted. Here `result`
# is what verdifax_attest() returned to a member key of the account.
verdifax_delete_run(owner, result$run_id, result$record_hash)
```

Each of these is signed by the owner key's request key, over `verdifax.owner-change-signature.v1`, the account's label (for example `account-7`, read from `verdifax_get_account()` unless you pass `account_id`), the change, its subject, the time and a fresh nonce. Verdifax never holds the owner's request key, so it cannot make a signature with it, and `verdifax-verify --signals --owner-request-key` confirms every owner change in the feed was signed with the owner's key. A client without a `signing_key` is refused before anything is sent. Setting a value already set changes nothing and returns `account_change` as `NULL`. Each call stops with an error when the record the server returns does not carry what was sent: the change and value, or the run and record hash, `decided_by` `owner`, and the signature, time and nonce sent, under the client's own request key. `verdifax_delete_run()` takes a completed run's `record_hash`, or a stopped run's receipt hash; the server answers HTTP 409 for another hash, and for a public record, which is withdrawn first with `verdifax_unpublish_run()`.

An admin key starts the replacement of a lost owner key with `verdifax_admin_replace_owner_key(admin, account_id)`, on the owner's written request, and deletes a record as Verdifax's decision with `verdifax_admin_delete_run(admin, run_id)`. Each is sealed in the account's feed with `decided_by` `verdifax_admin`, and each is refused with HTTP 409 while the owner blocks it. A replacement emails a one-time link, valid for 72 hours, to the address on file, and the new owner key is made when the owner opens it, so the response holds neither the link nor a key. `verdifax-verify --signals` fails a feed that shows a Verdifax replacement or deletion after the owner's block.

## Sign-off

A sign-off is an approver's decision, approve or reject, on one exact result: a completed run's record, a refused or halted run's receipt, or a whole job by its final step. The account's owner registers approver keys. The approver signs on their own machine with the approver key, which is never sent, and any key in the account can submit the sign-off.

```r
# On the approver's machine: make the key pair and its proof. Store
# private_key as a secret: it is 32 raw bytes and is never sent.
approver_key <- verdifax_generate_request_key()$private_key
proof <- verdifax_approver_key_proof(approver_key) # public_key and proof

# The owner registers the approver from the proof alone, and never holds
# the private key. A proof that does not verify is refused before sending.
owner <- verdifax_client(api_key = owner_secret)
approver <- verdifax_register_approver(owner, proof, "Dana, credit review")
verdifax_list_approvers(owner)$approvers

# The digest of a completed run's record is the anchored_digest of its
# bundle_anchor.
member <- verdifax_client(api_key = member_secret)
bundle <- jsonlite::fromJSON(verdifax_get_run_artifacts(member, 42))
signoff <- verdifax_sign_off(
  member,
  target = list(kind = "record", run_id = 42, digest = bundle$bundle_anchor$anchored_digest),
  decision = "approve",
  approver_key = approver_key,
  note = "Checked against the loan file."
)
signoff$sequence

# The sign-offs on the run, oldest first, as the exact text the server sent.
# The newest is the decision in force, except on a job's final step, where
# the newest sign-off on the whole job governs. Save it and check it offline
# beside the run's record.
writeLines(verdifax_get_signoffs(member, 42), "signoffs.json", sep = "")
writeLines(verdifax_get_run_artifacts(member, 42), "bundle.json", sep = "")
# verdifax-verify --signoff signoffs.json bundle.json

# The owner saves the account's whole chain and checks it offline.
# The chain ends with its head statement, anchored on the public log, so the
# verifier reports the history complete as of that time (since v0.31.0).
writeLines(verdifax_get_signoff_history(owner), "signoff-history.json", sep = "")
# verdifax-verify --signoff-history signoff-history.json

# The owner revokes an approver key. Its earlier sign-offs stay on the record.
verdifax_revoke_approver(owner, approver$id)
```

An approver key is registered by the account's owner and is never a request key in the same account, so the key that requested a run cannot sign it off. The server refuses one with HTTP 409, and `verdifax_register_approver()` and `verdifax_sign_off()` refuse the client's own `signing_key` before sending. `verdifax_register_approver()` takes either the list `verdifax_approver_key_proof()` returns, checked here, or the approver's private key, from which it makes the proof here.

A sign-off shows that the holder of a registered approver key signed that decision on that exact result, and that Verdifax logged it on the public log. It does not show the review was careful, the result right, or who the person is: a key is not an identity. It gates nothing on its own. A later sign-off on the same result supersedes the earlier one, and nothing is deleted. Verdifax did not review the result.

The target names the result by what its public-log entry covers. For a record, `kind = "record"` and `digest` is the `anchored_digest` of the `bundle_anchor` in the text from `verdifax_get_run_artifacts()`. For a receipt, `kind = "receipt"` and `digest` is the receipt's `hash`. For a job, `kind = "job"`, `run_id` is the final step's run, `job_id` names the job, and `digest` is the final step's record digest, read as for a record. A target the server cannot match to a result of the account with that digest answers HTTP 409.

`verdifax_sign_off()` reads the account's chain and newest sign-off with `verdifax_get_newest_signoff()`, then signs `verdifax.signoff.v1`, the chain, the newest sign-off, the target, the decision, the note's hash, the time and a fresh nonce, joined by zero bytes. The note's text never leaves this machine: only its SHA-256 is sent, as `note_hash`. With no note, `note_hash` is left out, and an empty note is refused. Bad input is refused before anything is sent. An HTTP 409 can also mean another sign-off came first, and the call stops with the server's message and is not retried. The call also stops with an error when the record the server returns does not carry the signature, `approver_key`, `decision`, `previous_signoff_hash` and `target` that were sent. `verdifax_signoff_preimage()` and `verdifax_approver_key_proof()` build the signed bytes and the proof without sending anything.

A member key submits on `/signoffs`, for any result of its account, and reads `/runs/{id}/signoffs` for the runs it made. The owner key passes `as_owner = TRUE` to `verdifax_get_newest_signoff()`, `verdifax_sign_off()` and `verdifax_get_signoffs()` to use the `/account` routes, which cover every run of the account. The owner's `verdifax_export_account_runs()` also holds `signoffs`, the account's whole chain.

The verifier reads sign-offs since v0.22.0: `verdifax-verify --signoff FILE` checks a record's or receipt's sign-offs as `verdifax_get_signoffs()` returns them, and `--signoff-history FILE` checks the account's whole chain.

## Signal feed

The signal feed is every control signal Verdifax recorded for the account, in order, each with its sealed entry, or, for an event whose record was deleted, that record's tombstone: a run sealed (`run.sealed`), a run refused, halted or failed, a policy change, a sign-off, an approver key registered or revoked, a key created or revoked, a record made public or withdrawn (`run.published`, `run.unpublished`), an account change (`account.changed`), a record deleted (`run.deleted`), a restore gap (`chain.gap`) and an interrupted entry (`chain.interrupted`). A key change may be `verdifax.key-change.v2`, which names who decided it in `decided_by`. An account change also seals each key's own request key: `request_key.registered` with the new public key, `request_key.rotated` with the new public key and `request_key_approval`, the previous key's signature over the change, and `request_key.cleared`, approved the same way when the key's holder clears it and with no approval when Verdifax does. Each event is a CloudEvent. The feed cannot show a signal Verdifax never recorded.

A page that reaches the feed's end also holds `head`, Verdifax's statement of the feed's highest event (`verdifax.feed-head.v1`, with `account`, `sequence`, `head_hash`, `stated_at`, `head_statement_hash` and `anchor`, its entry on the public log). The head is not an event. Save it with the feed: `verdifax-verify --signals` checks the feed against it, so a feed cut short before a later event fails.

The owner key creates a feed key, which reads the feed and nothing else, and can read the same feed itself with `as_owner = TRUE`.

```r
owner <- verdifax_client(api_key = owner_secret)
feed_key <- verdifax_create_feed_key(owner, "siem")

# Follow the feed from the start, or from the last sequence you saved. The
# server holds each read up to 25 seconds for a new event.
feed <- verdifax_client(api_key = feed_key$secret)
verdifax_follow_signals(feed, function(event) {
  message(event$data$sequence, " ", event$type)
  saveRDS(event$data[c("sequence", "event_hash")], "last-event.rds") # your place, to resume
  TRUE # return FALSE to stop
}, after = 0, on_head = function(head) {
  saveRDS(head, "feed-head.rds") # the head through the events handled
})
```

`verdifax_follow_signals()` reads each page from the `next_after` of the one before, so no event is skipped. When a read fails, it stops with an error of class `verdifax_follow_error` whose `after` is the last sequence handled and whose `after_event_hash` is that event's `event_hash`: call it again with both, as `after` and `after_event_hash`, to go on. It never passes the feed's head to the handler as an event. It keeps a page's head only once the handler has handled every event on that page, and only when the head's `sequence` is the page's `next_after` and its `head_hash` is the `event_hash` of the last event handled, so a kept head states the feed through the events you handled. To resume at the feed's end and still keep the head, save each event's `event_hash` with its sequence and pass it back as `after_event_hash`; the head statement already kept, served again on an idle read, is not kept again, while a fresh statement for the same sequence replaces it. `on_head` receives each head as it is kept, the value returned holds it as its `head` attribute, and a `verdifax_follow_error` holds it as `head`. For an event whose entry is a record that was deleted, for example a refused run's receipt event, `entry` is `NULL` and `deleted` holds the record's tombstone, with `log_entries`, the public-log entries of the deleted record, and, for a job step deleted from round 61 on, `job_links`, the step's own links (`previous_record_hashes`, `external_previous` and `final`). `verdifax_get_signals()` reads one page with `after`, `limit` (1 to 500) and `wait` (0 to 25 seconds). Its HTTP timeout is at least the wait plus 30 seconds. `verdifax_signal_event_hash()` recomputes an event's `event_hash`, and `verdifax-verify --signals` checks a saved feed.

`verdifax_pending_signoffs(events)` returns, in feed order, the run ids whose allowing policy rule requires a person's sign-off (their `run.sealed` event says `signoff_required`) and on which no approval is in force, read as `verdifax-verify` reads it: the latest sign-off on the run's whole job governs when there is one, and otherwise the latest sign-off on its record; a receipt sign-off does not count. A run whose record was deleted, by a `run.deleted` event anywhere in the events given, is left out; the server keeps the run's `run.sealed` event and its entry, and a `run.sealed` or `run.deleted` event whose entry names no run (a positive whole number) stops with an error. Pass the feed from its start, or pages that include each run's sign-offs and deletion. It makes no request.

A webhook posts each new event to an `https://` address, signed under the Standard Webhooks scheme. A delivery is a copy: the pull feed and the public log are the record. Check each delivery on the raw body bytes, before any JSON parsing:

```r
hook <- verdifax_create_webhook(owner, "https://hooks.example.com/verdifax",
                                types = c("run.refused", "run.halted"))
# Store hook$secret (whsec_...) as a secret. It is shown once.

# In the receiving server, with the request's headers and raw body:
event <- verdifax_verify_webhook(headers, raw_body, webhook_secret)
event$data$kind
```

`verdifax_verify_webhook()` refuses a `webhook-timestamp` more than 300 seconds from now, in either direction, and accepts the delivery when any `v1` signature in `webhook-signature` matches, compared in constant time. A failed check stops with an error of class `verdifax_webhook_error` that says which check failed. `verdifax_list_webhooks()`, `verdifax_delete_webhook()` and `verdifax_list_webhook_deliveries()` manage the subscriptions and show each delivery's attempts.

`verdifax_get_failure_receipt()` returns the failure receipt of a run that failed, as the exact JSON text the server sent.

## Provider helpers

`verdifax_attest_claude_response()` and `verdifax_attest_openai_response()` attest a prompt and response as one payload: canonical JSON, exactly `{"prompt":...,"provider":...,"response":...}` with sorted keys and no extra whitespace, UTF-8, with `provider` set to `anthropic` or `openai`. `verdifax_format_provider_payload()` builds that text. All four Verdifax SDKs produce the same bytes.

Both take an optional `job` block and return what `verdifax_attest()` returns, including `record_hash` and `signed_request`, and their errors hold both too. `govern` is `FALSE` by default. Set `govern = TRUE` to also send the response text as `ai_output_text` for the AIVP review, which runs on Anthropic in production. Without it, the AI output text is not sent for review.

## Optional execute fields

`verdifax_attest()`, `verdifax_execute()`, `verdifax_execute_batch()` and `verdifax_verify_determinism()` accept `attested_context`, `reproducibility_context`, `request_substance`, `authorization_chain`, `regulatory_scaffolding` and `causal_graph`. In a completed run's sealed record each is recorded as supplied, except the values the server observes itself (in `request_substance`, `latency.total_ms`, the authentication method and key, and the origin hashes it fills; in `regulatory_scaffolding`, empty data-residency regions it fills), and Verdifax does not check that what you declare is true. A refused or halted run's receipt holds none of these blocks, but its `receipt_context` seals the declared policy inputs (such as subject and object identifiers) when the policy names its author and its rules ran. An `attested_context` field name outside `attested` (which the client sets itself from the fields you provide), `actor_id`, `actor_role`, `authorization_policy`, `actor_signature`, `model_provider`, `model_name`, `model_version`, `model_temperature`, `prompt_hash`, `decision_kind`, `decision_result` and `decision_note` is refused before sending, so a misspelt field is never dropped. They also accept `policy_context` and `expected_policy_hash`, which are checked before sending: see [Policies](#policies). Write a JSON array as an unnamed list, so that one item stays an array. The client derives `attested` and `declared` from the fields you provide. Leave out `request_substance$origin$source_ip_hash` and `user_agent_hash`: the server computes them. `verdifax_attest()`, `verdifax_execute()` and `verdifax_verify_determinism()` refuse them before sending, and a batch row that sets them fails in `results`.

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
status `probe`, or `stage_error` for a replay that sealed nothing or
whose record could not be anchored on the probe's in-process ledger.

## Request signing

A trial key, which is what a pilot receives, needs a request key: it seals nothing until one is registered. Its holder can then replace the request key but not clear it; only Verdifax can clear it, for a holder who lost it, after which the trial key again seals nothing until a new one is registered, and for a key in an account the clearing is sealed in that account's feed as an account change. On a production key, request signing is optional, and a client with no signing key sends the same requests as before.

You can register an Ed25519 public key on your API key, so that each run must also be signed with a private key that only you hold. The key pair is created on your machine, and Verdifax receives only the public key. Signing needs the `sodium` package:

```r
install.packages("sodium")
```

```r
# Run once, then store private_key as a secret. It is 32 raw bytes.
keys <- verdifax_generate_request_key()

client <- verdifax_client(signing_key = keys$private_key)
verdifax_register_request_key(client) # sends the public key with its proof

# verdifax_attest(), verdifax_execute_batch(),
# verdifax_verify_determinism(), verdifax_activate_policy(),
# verdifax_activate_account_policy(), verdifax_set_account_setting() and
# verdifax_delete_run() now sign.
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

Once a key is registered, the server needs that key to approve replacing or clearing it. `verdifax_rotate_request_key()` and `verdifax_clear_request_key()` send that approval, so call them with a client that holds the current key. For a key in an account, each registration, replacement and clear by the key's holder is sealed in the account's signal feed as an account change (`request_key.registered`, `request_key.rotated`, `request_key.cleared`), the replacement and the clear with that approval, so the feed shows each key's chain of request keys. When another change to the key's request key came first, the server answers HTTP 409 "the request key changed since this change was signed": the call stops with the server's message, as an `httr2_http_409` error, and the client keeps its key. After a rotate the client and its copies sign with the new key. After a clear they drop the key and send unsigned requests, because the server refuses a signed run on an API key with no registered key. If the key is lost, an admin can clear it with `verdifax_admin_clear_request_key()` after a manual check.

In a batch each row carries its own signature and nonce, and the server checks them as it reaches that row. A row refused for its signature comes back in `results`, so a repeated batch returns HTTP 200 with failed rows, and a row reached more than five minutes after it was signed fails the same way. A determinism check uses one signature for the request, and repeating it returns HTTP 403.

A signature shows who requested the run, not that they accepted the outcome.

## Dependencies

- `httr2 (>= 1.1.0)`, HTTP client
- `jsonlite (>= 1.8.0)`, JSON serialization
- `openssl`, SHA-256 for the canonical hash functions and HMAC-SHA256 for checking webhooks
- `sodium`, optional, needed only for request signing

All are available on CRAN.

## License

MIT, see `LICENSE`.

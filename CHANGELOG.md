# verdifax 1.10.0

## Successful runs in the feed, restore gaps, a required AI review, reports that print the AI's answer, and the account's time zone

* The signal feed carries two new kinds: `run.sealed`, a successful run's record naming the run and the exact record it sealed, and `chain.gap`, a restore gap that names the places a chain skips after a restore from backup. `verdifax-verify --signals` reads both since v0.28.0.
* `verdifax_test_policy()` and `verdifax_test_account_policy()` take `ai_output_declared = TRUE` to test a policy whose `ai_review` sets `"required": true`: the server refuses, with reason `ai_review_required`, a step under the requirement that declares no AI output.
* `verdifax_download_audit_pdf(client, run_id, format, ai_output_text = ...)` sends the AI's exact answer, and the report prints it on its first page, marked as supplied, only when its SHA-256 is the hash the record seals; other text stops with the server's reason (HTTP 422). `verdifax_download_public_audit_pdf()` reads a published record's audit PDF with no key.
* `verdifax_set_account_time_zone()` (owner key) sets the second time zone the account's audit PDFs show beside UTC: an IANA zone, `"none"` for UTC alone, or `""` for the server region's zone.

# verdifax 1.9.0

## The AI review says what it found, and the trace that proves it comes back to you

* When an account's AI review runs on a step's AI output, the record seals what it found: the review setup (prompt and model), the SHA-256 of the trace it checked, the checker, what the account policy chose a contradiction finding does (`halt` or `record`), the outcome (`clean`, `halted` or `recorded`) and the finding (two trace nodes and the opposing terms). Verdifax returns the trace once and does not store it; keep it to re-run the check with `verdifax-verify --aivp-trace` (or `--aivp-traces` for a job), since v0.27.0.
* A completed run's result carries the trace as `aivp_trace_text` and the sealed review as `manifest$AivpReview`; the error of a run the review halted carries the trace as `aivp_trace_text`.

# verdifax 1.8.0

## A publication says who decided

* A run publication is now `verdifax.run-publication.v2` and seals who decided: `owner`, the account's owner key, or `verdifax_admin`, a Verdifax admin key, which can withdraw any public record and publish only records it made itself. Every change to a record's public state, Verdifax's included, is now sealed in the feed of the record's account. The publication list carries it as `decided_by`. Publications sealed before v2 are v1, carry no `decided_by`, and were the owner's. `verdifax-verify --signals` reads v2 since v0.26.0.

# verdifax 1.7.1

* The same code as 1.7.0, whose tagged commit failed one test in CI: the test read the package's internal list of signal kinds without naming the package, which works only when the tests run inside the package. It now names it, and the release is tagged on a commit whose CI passed.

# verdifax 1.7.0

## A published stopped run is served as its sealed receipt

* `verdifax_publish_run()` and `verdifax_unpublish_run()` return `public_receipt_url`, the address of a stopped run's receipt while it is public, `/public/runs/{token}/receipt.json`; a stopped run has no bundle address, so `public_bundle_url` is absent for it. `verdifax-verify` checks the receipt address as it checks a saved receipt.
* `verdifax_get_public_receipt_by_token(client, token)` reads a published stopped run's sealed receipt from `GET /public/runs/{token}/receipt.json`, as the exact text the server sent, with no key.

# verdifax 1.6.0

## The account owner publishes the account's records

* `verdifax_publish_run(client, run_id)` makes a record made by any key of the account public on its random link with `POST /account/runs/{id}/publish`, and `verdifax_unpublish_run()` withdraws it with `/unpublish`, keeping the link for a later publish. Both need the owner key and return the run's public state, its links while public, and `publication`, the run publication the call sealed (`verdifax.run-publication.v1`: the run, its record hash, its job and step, the time and its place in the account's signal feed), or `NULL` when the run was already in the asked state. The service's admin key cannot publish another key's record.
* Signal kinds `run.published` and `run.unpublished`; `verdifax-verify --signals` reads them since v0.24.0.

# verdifax 1.5.0

## Signal feed

* The signal feed is every control signal Verdifax recorded for the account, in order, each with its sealed entry: a run refused, halted or failed, a policy change, a sign-off, an approver key registered or revoked, and a key created or revoked. Each event is a CloudEvent that carries its place in the feed and the hash of the event before it. The feed cannot show a signal Verdifax never recorded.
* `verdifax_get_signals()` reads one page of the feed with a feed key, or the owner key's `/account/signals` with `as_owner = TRUE`. It takes `after`, the last sequence read, `limit` from 1 to 500, and `wait` from 0 to 25 seconds, and refuses anything else before sending. Its HTTP timeout is at least the wait plus 30 seconds, whatever the client's own timeout.
* `verdifax_follow_signals()` reads page after page from `after` and calls a handler on each event, in order, until the handler returns `FALSE`. It reads each page from the `next_after` of the one before, so no event is skipped, and asks the server to wait for an event when a page is empty. A failed read is retried with the client's retry policy. It never loses its place: when a read fails, a page is out of order, or the handler raises an error, it stops with an error of class `verdifax_follow_error` whose `after` is the last sequence handled.
* `verdifax_create_feed_key()` and `verdifax_revoke_feed_key()` let the owner key create and revoke feed keys. A feed key reads the feed and nothing else.
* `verdifax_signal_event_hash()` recomputes an event's `event_hash` without calling the server. It matches the vector the four SDKs share. `verdifax-verify --signals` checks a saved feed.

## Webhooks

* `verdifax_create_webhook()`, `verdifax_list_webhooks()`, `verdifax_delete_webhook()` and `verdifax_list_webhook_deliveries()` let the owner key subscribe an `https://` address to some or all signal kinds, list and delete the subscriptions, and read a subscription's delivery log. The types must be distinct signal kinds, and a bad address or type is refused before sending. The server checks the address too.
* A webhook delivery is a copy: the pull feed and the public log are the record.
* `verdifax_verify_webhook()` checks a delivery under the Standard Webhooks scheme and returns its CloudEvent. It takes the `whsec_` secret, matches header names whatever their case, refuses a `webhook-timestamp` more than `tolerance_seconds` (300 by default) from now in either direction, and accepts the delivery when any `v1` signature in `webhook-signature` matches the raw body, compared in constant time. A failed check stops with an error of class `verdifax_webhook_error` that says which check failed. The secret is never shown in a message. It matches the vector the four SDKs share.

## Failure receipts

* `verdifax_get_failure_receipt()` returns the failure receipt of a run that failed as the exact JSON text the server sent. A failed run from before failure receipts answers HTTP 404.

## Other changes

* The default user agent is `verdifax-r/1.5.0`.

# verdifax 1.4.0

## Sign-off

* An approver's sign-off is a decision, approve or reject, on one exact result: a completed run's record, a refused or halted run's receipt, or a whole job by its final step.
* `verdifax_register_approver()`, `verdifax_list_approvers()` and `verdifax_revoke_approver()` let the account's owner key register, list and revoke approver keys. `verdifax_register_approver()` takes the list with `public_key` and `proof` that `verdifax_approver_key_proof()` returns on the approver's machine, so the owner never holds the approver's private key, and refuses a proof that does not verify before sending. Given the approver's private key instead, it makes the proof here, and the key is never sent. An approver key is never a request key in the same account: the server refuses one, and the client's own `signing_key` is refused before sending. A revoked key's earlier sign-offs stay on the record.
* `verdifax_sign_off()` checks its input, reads the account's chain and newest sign-off, hashes the note here, signs the decision with the approver key and submits it. Bad input is refused before anything is sent. The note's text is never sent, only its SHA-256 as `note_hash`. With no note, `note_hash` is left out, and an empty note is refused. The call stops with an error when the record the server returns does not carry the signature, `approver_key`, `decision`, `previous_signoff_hash` and `target` that were sent. A record's digest is the `anchored_digest` of its `bundle_anchor` from `verdifax_get_run_artifacts()`, and a receipt's is its `hash`.
* `verdifax_get_newest_signoff()` reads the account's newest sign-off. `verdifax_get_signoffs()` returns a run's sign-offs as the exact JSON text the server sent, for `verdifax-verify --signoff`, and `verdifax_get_signoff_history()` returns the account's whole chain the same way, for `verdifax-verify --signoff-history`. Save either with `writeLines(text, path, sep = "")`.
* `verdifax_get_newest_signoff()`, `verdifax_sign_off()` and `verdifax_get_signoffs()` take `as_owner = TRUE` to use the owner key's `/account` routes.
* `verdifax_signoff_preimage()` and `verdifax_approver_key_proof()` build the signed bytes and the proof without sending anything. Both match the vector the four SDKs share.
* A sign-off shows that the holder of a registered approver key signed that decision on that exact result, and that Verdifax logged it on the public log. It does not show the review was careful, the result right, or who the person is: a key is not an identity. It gates nothing on its own. A later sign-off on the same result supersedes the earlier one, and nothing is deleted. Verdifax did not review the result.

## Other changes

* The owner's `verdifax_export_account_runs()` documents the new `signoffs` field, the account's whole chain of sign-offs, as the server sends it. The SDK passes it through unchanged.
* The default user agent is `verdifax-r/1.4.0`.

# verdifax 1.3.0

## Accounts

* An account is a company on Verdifax, and every API key belongs to one account for life. The account's owner key manages it with the new account functions, and its member keys run. An owner key cannot run anything.
* `verdifax_get_account()`, `verdifax_create_account_key()`, `verdifax_list_account_keys()` and `verdifax_revoke_account_key()` read the account and manage its member keys.
* `verdifax_register_account_request_key()` and `verdifax_clear_account_request_key()` register and clear the owner key's request key, with the same bodies as `verdifax_register_request_key()` and `verdifax_clear_request_key()`.
* `verdifax_list_account_runs()`, `verdifax_export_account_runs()` and `verdifax_export_account_runs_csv()` list and export the runs of every key in the account. The JSON export also holds `account_id` and the account's policy documents and changes.
* `verdifax_upload_account_policy()`, `verdifax_list_account_policies()`, `verdifax_get_account_policy()`, `verdifax_test_account_policy()`, `verdifax_get_account_policy_history()` and `verdifax_activate_account_policy()` manage the account's policy. Every key in the account must pass it on top of its own policy, and a run is admitted only when both allow. Verdifax did not write, review or approve it.
* `verdifax_activate_account_policy()` signs the change with the owner key's request key over the account's chain, for example `account-7`, as `verdifax_activate_policy()` signs. A client without a `signing_key` is refused before anything is sent, because the server refuses an unsigned change to an account's policy.
* `verdifax_admin_create_account()` and `verdifax_admin_list_accounts()` create an account with its first owner key and list every account.
* `verdifax_admin_create_key()` takes an optional `account_id` to put a new key in an existing account.
* The account number is a label Verdifax assigned, not a verified company identity.

## Other changes

* `verdifax_verify_determinism()` documents the new answer: the server now compares two refused or halted replays by the manifest hashes they sealed, each refused row carries its sealed `receipt`, and `diff$reason` says why there is no verdict when neither replay sealed a record.
* Every export row and every run in `verdifax_list_runs()` and `verdifax_list_account_runs()` now holds `api_key_id`, the id of the key that requested the run, as the server sends it. In the CSV it is the last column, after `step_id`. The SDK passes it through unchanged.
* An id given as `Inf` is refused before sending, as any other id that is not a positive whole number is.
* The default user agent is `verdifax-r/1.3.0`.

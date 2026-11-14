# verdifax 1.16.0

## Webhook changes signed by the owner and sealed in the feed

* From verifier v0.35.0's server release on, a webhook is added and removed only with its record in the account's feed: an `account.changed` event, `webhook.subscribed` or `webhook.deleted`, decided by the owner and signed by the owner key's request key over the webhook's value, `sha256=` and the SHA-256 of the address exactly as sent, then ` kinds=` and the kinds sorted and joined with commas, or `all`. The record never holds the address, which can carry a token, so Verdifax, which never holds the owner's request key, cannot add a destination for the account's events. The server refuses an address not sent in the form it stores, with a 400 naming that form.
* `verdifax_create_webhook(client, url, types = NULL, account_id = NULL)` and `verdifax_delete_webhook(client, id, account_id = NULL)` sign the change with the client's `signing_key`, the owner key's request key, and stop before anything is sent without one. `verdifax_delete_webhook()` reads the subscription from `verdifax_list_webhooks()` and signs its value; an id the account holds no live webhook with stops before the removal is sent. Both check the record in the answer, `account_change`: it must carry the change, the value, `decided_by` owner and the signature sent, or the call stops.
* `verdifax_webhook_value(url, types)` returns the value; it makes no request. The shared vector `sdk-webhook-change-vector.json` fixes the value for the four SDKs, the server and the verifier, and a test here reads it.
* The owner-replacement setting's description now says that, from verifier v0.35.0's server release on, Verdifax also cannot clear the owner key's request key while the owner blocks owner-key replacement.
* The user agent is `verdifax-r/1.16.0`.

# verdifax 1.15.0

## The feed's head, and each key's request key sealed in the feed

* A page of the signal feed that reaches the feed's end now holds `head`, Verdifax's statement of the feed's highest event, `verdifax.feed-head.v1`: `account`, `sequence`, `head_hash`, `stated_at`, `head_statement_hash` and `anchor`, its entry on the public log. `verdifax_get_signals()` returns it with the page. `verdifax-verify --signals` checks a saved feed against it, so a feed cut short before a later event fails.
* `verdifax_follow_signals()` never passes the head to `handler` as an event. It keeps a page's head only once `handler` has handled every event on that page without stopping, and only when the head's `sequence` is the page's `next_after` and its `head_hash` is the `event_hash` of the last event handled, so a kept head always states the feed through the events you handled. Before `handler` handles an event, the new `after_event_hash` argument gives the `event_hash` of event `after`, as you saved it, so a follower resuming at the feed's end keeps the head it is served; without it, no head is kept until an event is handled. A value that is not 64 lowercase hex characters is refused before any request. The head statement already kept (the same `head_statement_hash`), served again on an idle read, is not kept again, while a fresh statement for the same sequence, made once the server's 5-minute reuse ends, replaces it. The shared vector `sdk-feed-head-vector.json` holds the four SDKs to this rule. The new `on_head` argument takes a function called with each head as it is kept, after its page's events; the value returned holds the kept head as its `head` attribute, and a `verdifax_follow_error` holds it as `head`. A page whose head is not an object stops following, as a malformed page does.
* Two round 60 fields are now documented and tested: the tombstone's `log_entries`, the public-log entries of the deleted record, in `verdifax_delete_run()`'s `run_deletion`; and `deleted`, the tombstone a feed event carries in place of its `entry` when that entry is a record that was deleted, such as a refused run's receipt, which `verdifax-verify --signals` reads since v0.33.0.
* The feed's `account.changed` events now include each key's own request key: `request_key.registered`, with the new public key as `value`; `request_key.rotated`, with the new public key and `request_key_approval`, the previous key's signature over the change, which is the approval `verdifax_rotate_request_key()` sends; and `request_key.cleared` decided by `owner`, the holder's own clear, approved the same way over the empty key. A clear Verdifax decides carries no approval, as before.
* `verdifax_rotate_account_request_key(client, new_signing_key)` (owner key) replaces the owner key's request key at `POST /account/request-key`, as `verdifax_rotate_request_key()` does for a key's own: it sends the new key with its proof and the current key's approval, and the client and its copies switch to the new key only after the server accepts. A refusal, a 409 included, stops with the server's message and leaves the current key in place. The server seals it as `request_key.rotated`.
* A run deletion's tombstone (`verdifax.run-deletion.v1`) may carry `job_links`, the deleted job step's own links: `previous_record_hashes` and `external_previous`, lists of hashes, and `final`. It is on a job step deleted from this server release on, even when empty, and a tombstone written before carries none. The SDK reads it intact, with its lists kept as lists, in `verdifax_delete_run()`'s `run_deletion` and in a feed event's `deleted`, and its check of a returned tombstone accepts it.
* A `verdifax_follow_error` now also holds `after_event_hash`, the `event_hash` of the last event handled, or the one given when no event was handled, or `NULL` when none was given, so you can resume with both `after` and `after_event_hash` and keep the head at the feed's end.
* `verdifax_pending_signoffs()` and the follow loop read the new account changes and the head without stopping. `verdifax_pending_signoffs()` still refuses a `run.sealed` event that names no run, and leaves a run out once its `run.deleted` event appears; the server keeps a `run.sealed` event's own entry when the run's record is deleted. It now also refuses a `run.sealed` or `run.deleted` entry whose `run_id` is not a positive whole number, such as 0, as the other SDKs do; before, any number was taken. The shared vector `sdk-pending-signoffs-vector.json` holds the four SDKs to this rule.
* A request-key change whose key another change replaced first answers HTTP 409 "the request key changed since this change was signed". `verdifax_register_request_key()`, `verdifax_rotate_request_key()`, `verdifax_clear_request_key()`, `verdifax_register_account_request_key()`, `verdifax_rotate_account_request_key()` and `verdifax_clear_account_request_key()` stop with the server's message, as an `httr2_http_409` error, and the client keeps its key. `verdifax_register_request_key()` now carries the server's message on every error, as the other calls do.
* The user agent is `verdifax-r/1.15.0`.

# verdifax 1.14.0

## Settings and deletions the owner decides, each sealed, and execute bodies read strictly

* `verdifax_set_account_setting(client, setting, value)` (owner key) sets `owner-replacement` or `verdifax-deletion` to `allowed` or `blocked`. While a setting is blocked, Verdifax can neither replace the account's owner key nor delete its records. `verdifax_get_account()` returns both settings as `owner_replacement` and `verdifax_deletion`.
* `verdifax_delete_run(client, run_id, record_hash)` (owner key) deletes one of the account's records, named by its record hash. A tombstone is sealed in its place.
* Both are signed by the owner key's request key over `verdifax.owner-change-signature.v1`, the account's label, the change, its subject, the time and a fresh nonce. Verdifax never holds the owner's request key, so it cannot make a signature with it, and `verdifax-verify --signals --owner-request-key` confirms every owner change in the feed was signed with the owner's key. A client without a `signing_key` is refused before anything is sent. The account's label is read from `verdifax_get_account()` unless you pass `account_id`. Each call stops with an error when the record the server returns does not carry what was sent: the change and value, or the run and record hash, `decided_by` `owner`, and the signature, time and nonce sent under the client's own request key.
* `verdifax_admin_replace_owner_key(client, account_id)` and `verdifax_admin_delete_run(client, run_id)` (admin key) start the replacement of a lost owner key and delete a record as Verdifax's decision. Each is sealed in the account's feed and refused while the owner blocks it. A replacement emails a one-time link to the address on file, and the response holds neither the link nor a key.
* `verdifax_owner_change_preimage(account, change, subject, signed_at, nonce)` returns the exact bytes the owner's request key signs, to check an `owner_signature` in a sealed record. It makes no request.
* `verdifax_pending_signoffs(events)` leaves out a run whose record was deleted: a `run.deleted` event for its `run_id`, anywhere in the events given, removes it from the list.
* The signal feed carries two new kinds, `account.changed` and `run.deleted`, and a key change may be `verdifax.key-change.v2`, which names who decided it in `decided_by`. `verdifax_create_webhook()` takes both kinds. Webhook checks are unchanged.
* The server now refuses a field it does not know in an `/execute`, `/execute/batch` or `/execute/verify-determinism` body with HTTP 400, naming it. Every body the SDK builds holds only fields the server defines, and the SDK still refuses an unknown field in a batch row or an `attested_context` before sending.
* The user agent is `verdifax-r/1.14.0`.

# verdifax 1.13.0

## Sign-off read as the verifier reads it, and the sign-off history's head statement.

* `verdifax_pending_signoffs(events)` reads the decision in force as `verdifax-verify` does: the latest job sign-off on a run governs when there is one, and otherwise the latest record sign-off. A run approved by a sign-off on its whole job is no longer listed, and one whose job was rejected is, even when the step carries its own approval.
* `verdifax_get_public_signoff()` and `verdifax_get_public_signoff_by_token()`: `decision_in_force` names the kind of sign-off in force (`signed_as`), its place (`sequence`) and time (`signed_at`) and, when the job's decision governs, the result's own latest decision (`own_decision`). It is `NULL` for a step whose job's sign-offs could not be read.
* `verdifax_get_signoff_history()` returns a list that ends with the chain's head statement, `verdifax.signoff-head.v1`, anchored on the public log. `verdifax-verify --signoff-history` reports the history complete as of that entry's time, and requires the head when a rule requires a person's sign-off, since v0.31.0.
* The server now refuses a request that gives a query value more than once with HTTP 400. The SDK gives each value once.
* The user agent is `verdifax-r/1.13.0`.

# verdifax 1.12.0

## Data-quality declarations, pending sign-offs, public sign-offs, and requests read strictly

* `policy_context` takes `data_quality`: where the data came from (`source`), the time it describes (`as_of`, read as strictly as the server reads it) and the checks you ran on it (`checks`, each a `name` and a `result` of `"pass"`, `"fail"` or `"warn"`). It is sealed with the other policy values, and a policy's `data_quality` condition can require and test it. Verdifax judges none of it. The SDK checks it before sending, with the shared data-quality vector every SDK and the server test.
* `verdifax_pending_signoffs(events)` lists, in feed order, the runs whose allowing rule requires a person's sign-off and on which no approval is in force. It makes no request.
* `verdifax_get_public_signoff()` and `verdifax_get_public_signoff_by_token()` read the sign-off a published run's audit report prints, and for a step of a job, the job's decision in force. No API key needed.
* `verdifax_download_audit_pdf()` and `verdifax_download_public_audit_pdf()` take `fallback`. The server now refuses a report format it does not know with HTTP 400; `fallback = "comprehensive"` asks for the comprehensive report instead.
* `verdifax_list_runs()`, `verdifax_search_runs()`, `verdifax_list_account_runs()` and `verdifax_list_attestations()` take `lenient`. The server now refuses a value it cannot read, such as a date in a search, with HTTP 400; `lenient = TRUE` asks it to ignore or replace the value instead.
* The user agent is `verdifax-r/1.12.0`.

# verdifax 1.11.0

## Interrupted sign-offs and policy changes, exact records, and time limits

* The signal feed carries a new kind, `chain.interrupted`: a sign-off or policy change whose public-log entry was never confirmed has its place closed by a sealed, anchored record naming the entry it would have made. `verdifax-verify --signals`, `--signoff-history` and `--policy-history` accept a skipped place through one since v0.29.0. Records still come back as the exact text the server sent.
* Every CI job has its own time limit.

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

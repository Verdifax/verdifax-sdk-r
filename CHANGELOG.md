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

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

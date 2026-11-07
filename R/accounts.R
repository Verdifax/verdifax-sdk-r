# ----------------------------------------------------------------------------
# verdifax, accounts: the owner key's routes and the admin account routes
# ----------------------------------------------------------------------------
#
# An account is a company on Verdifax. Every API key belongs to one account
# for life. The account's owner key manages its member keys, its policy and
# its runs, and cannot run anything: the server refuses it with HTTP 403 on
# the routes that run or read runs. Member keys are the keys that run.
#
# The account number is a label Verdifax assigned, not a verified company
# identity. An account policy is the customer's own: Verdifax did not write,
# review or approve it.

.ACCOUNT_PATH <- "/account"
.ACCOUNT_KEYS_PATH <- "/account/keys"
.ACCOUNT_REQUEST_KEY_PATH <- "/account/request-key"
.ACCOUNT_RUNS_PATH <- "/account/runs"
.ADMIN_ACCOUNTS_PATH <- "/admin/accounts"
.ACCOUNT_ACTIVATION_UNSIGNED <- paste0(
  "an account policy change must be signed by the owner key's request key: ",
  "construct the client with signing_key and register it with ",
  "verdifax_register_account_request_key(), so no change was asked for"
)

# A single non-empty string, or NULL when optional and not given.
.account_string <- function(value, name, required = FALSE) {
  if (is.null(value) && !required) {
    return(NULL)
  }
  if (!is.character(value) || length(value) != 1 || is.na(value) || !nzchar(value)) {
    stop(name, if (required) " is required" else " must be a single string", call. = FALSE)
  }
  as.vector(value)
}


# ── Account ─────────────────────────────────────────────────────────────────

#' Read the owner key's account.
#'
#' Calls `GET /account` with the account's owner key. The account number is
#' a label Verdifax assigned, not a verified company identity.
#'
#' @param client A client handle from `verdifax_client()`, holding the
#'   account's owner key as `api_key`.
#'
#' @return Parsed API response list with `ok`, `account_id` (a label such
#'   as `"account-7"`), `id`, `name`, `tier`, `created_at`, `member_keys`
#'   and `owner_keys` (counts of keys not revoked) and `chain_id`, the chain
#'   of the account's policy changes.
#'
#' @export
verdifax_get_account <- function(client) {
  .perform(.get(client, .ACCOUNT_PATH))
}


# ── Member keys ─────────────────────────────────────────────────────────────

#' Create a member key in the owner key's account.
#'
#' Calls `POST /account/keys`. The key takes the account's tier and belongs
#' to the account for life. A trial key seals nothing until a request key is
#' registered on it, so `request_key_required` says whether it needs one.
#'
#' @inheritParams verdifax_get_account
#' @param name The key's name, a single non-empty string.
#' @param expires_at Optional expiry, an RFC 3339 time or a `YYYY-MM-DD`
#'   date.
#'
#' @return Parsed API response list with `ok`, `id`, `name`, `account_id`,
#'   `owner` (`FALSE` for a member key), `tier`, `created_at`, `secret`,
#'   `request_key_required` and `hint`. It holds the secret once.
#'
#' @export
verdifax_create_account_key <- function(client, name, expires_at = NULL) {
  body <- list(name = .account_string(name, "name", required = TRUE))
  body$expires_at <- .account_string(expires_at, "expires_at")
  .send(client, "POST", .ACCOUNT_KEYS_PATH, body)
}

#' List the keys in the owner key's account, without their secrets.
#'
#' Calls `GET /account/keys`.
#'
#' @inheritParams verdifax_get_account
#'
#' @return Parsed API response list with `ok`, `account_id` and `keys`.
#'   Each key holds `id`, `name`, `account_id`, `owner`, `tier`,
#'   `created_at`, `last_used_at`, `run_count`, `revoked` and, when it has
#'   one, `expires_at`.
#'
#' @export
verdifax_list_account_keys <- function(client) {
  .perform(.get(client, .ACCOUNT_KEYS_PATH))
}

#' Revoke one of the account's member keys.
#'
#' Calls `DELETE /account/keys/{id}`. A key in another account, or an owner
#' key, answers HTTP 404, and the call stops with the server's message.
#'
#' @inheritParams verdifax_get_account
#' @param key_id The member key's id, a positive whole number.
#'
#' @return Parsed API response list with `ok`, `id` and `revoked`.
#'
#' @export
verdifax_revoke_account_key <- function(client, key_id) {
  .send(client, "DELETE", paste0(.ACCOUNT_KEYS_PATH, "/", .require_id(key_id, "key_id")))
}


# ── The owner key's request key ─────────────────────────────────────────────

#' Register the client's public key as the owner key's request key.
#'
#' Calls `POST /account/request-key` with the same body as
#' `verdifax_register_request_key()`: the public key with a proof that this
#' client holds the private key. The server needs this key to sign every
#' change to the account's policy.
#'
#' @param client A client handle from `verdifax_client()`, holding the
#'   account's owner key as `api_key` and constructed with `signing_key`.
#'
#' @return Parsed API response list with `ok` and `public_key`.
#'
#' @export
verdifax_register_account_request_key <- function(client) {
  signer <- .active_signer(client)
  if (is.null(signer)) {
    stop(
      "verdifax_register_account_request_key needs a client with signing_key",
      call. = FALSE
    )
  }
  .send(client, "POST", .ACCOUNT_REQUEST_KEY_PATH, .request_key_body(signer))
}

#' Clear the owner key's request key.
#'
#' Calls `DELETE /account/request-key` with the same body as
#' `verdifax_clear_request_key()`. Once a key is registered, the server
#' needs that key to approve clearing it, so call this with a client that
#' holds it. After success the client drops its signing key, and so does
#' every copy of the client. After a failure it keeps the key. Until another
#' key is registered, the account's policy cannot be changed, because every
#' change must be signed.
#'
#' @inheritParams verdifax_get_account
#'
#' @return Parsed API response list with `ok`.
#'
#' @export
verdifax_clear_account_request_key <- function(client) {
  signer <- .active_signer(client)
  body <- if (!is.null(signer)) list(change = .key_change(signer, ""))
  result <- .send(client, "DELETE", .ACCOUNT_REQUEST_KEY_PATH, body)
  if (!is.null(signer)) {
    .drop_signer(signer)
  }
  result
}


# ── The account's runs ──────────────────────────────────────────────────────

#' List the runs of every key in the owner key's account.
#'
#' Calls `GET /account/runs`. It covers the runs the account's keys made
#' through Verdifax, not runs made elsewhere.
#'
#' @inheritParams verdifax_get_account
#' @param limit Optional page size. The server caps it at 500.
#' @param offset Optional number of rows to skip.
#'
#' @return Parsed API response list with `total`, `limit`, `offset` and
#'   `runs`, as from `verdifax_list_runs()`. Each run holds `api_key_id`,
#'   the id of the account's key that requested it.
#'
#' @export
verdifax_list_account_runs <- function(client, limit = NULL, offset = NULL) {
  .perform(.get(client, .ACCOUNT_RUNS_PATH, .query(limit = limit, offset = offset)))
}

#' Export the runs the server holds for every key in the account in a period.
#'
#' Calls `GET /account/runs/export` with the same query as
#' `verdifax_export_runs()`. Failures are included, up to 10,000 rows, and
#' `truncated` is `TRUE` when the period holds more. The list states what
#' was stored, not a verdict. It covers the runs the account's keys made
#' through Verdifax, not runs made elsewhere.
#'
#' @inheritParams verdifax_get_account
#' @param from Optional RFC 3339 time, inclusive.
#' @param to Optional RFC 3339 time, exclusive. Defaults to the time of the
#'   request.
#' @param job_id Optional job. Limits the export to that job's runs.
#'
#' @return Parsed API response list as from `verdifax_export_runs()`, with
#'   `account_id` and, once the account has policy documents,
#'   `account_policy_documents` and `account_policy_history`. Each row holds
#'   `api_key_id`, the id of the account's key that requested the run.
#'
#' @export
verdifax_export_account_runs <- function(client, from = NULL, to = NULL, job_id = NULL) {
  .export_runs_json(client, .ACCOUNT_RUNS_EXPORT_PATH, from, to, job_id)
}

#' Export the same rows as `verdifax_export_account_runs()` as CSV.
#'
#' `total` and `truncated` come from the response headers. Check
#' `truncated`: when `TRUE`, the CSV is missing rows for the period. The
#' call stops with an error when the server does not send those headers,
#' so that a cut-off export cannot pass for a complete one.
#'
#' @inheritParams verdifax_export_account_runs
#'
#' @return A list with `csv`, the CSV text as a single string, `total`,
#'   the runs held for the period, and `truncated`.
#'
#' @export
verdifax_export_account_runs_csv <- function(client, from = NULL, to = NULL, job_id = NULL) {
  .export_runs_csv(
    client, .ACCOUNT_RUNS_EXPORT_PATH, from, to, job_id, "verdifax_export_account_runs"
  )
}


# ── The account's policy ────────────────────────────────────────────────────

#' Upload a policy document for the owner key's account.
#'
#' Calls `POST /account/policies`, with the same body and response as
#' `verdifax_upload_policy()`. Nothing changes until the document is
#' activated with `verdifax_activate_account_policy()`. An account policy is
#' your own: Verdifax did not write, review or approve it. Once active,
#' every key in the account must pass it on top of its own policy, and a
#' run is admitted only when both allow.
#'
#' @inheritParams verdifax_get_account
#' @param document The policy's exact text, a single string, as for
#'   `verdifax_upload_policy()`.
#'
#' @return Parsed API response list with `policy_id`, `policy_version`,
#'   `policy_hash`, `document_hash` and `created_at`.
#'
#' @export
verdifax_upload_account_policy <- function(client, document) {
  .upload_policy_at(client, .ACCOUNT_POLICIES_PATH, document)
}

#' List the account's policy documents.
#'
#' Calls `GET /account/policies`.
#'
#' @inheritParams verdifax_get_account
#'
#' @return Parsed API response list as from `verdifax_list_policies()`,
#'   with `chain_id` naming the account, for example `"account-7"`.
#'
#' @export
verdifax_list_account_policies <- function(client) {
  .perform(.get(client, .ACCOUNT_POLICIES_PATH))
}

#' Read one of the account's policy documents.
#'
#' Calls `GET /account/policies/{document_hash}`.
#'
#' @inheritParams verdifax_get_account
#' @param document_hash 64-char lowercase hex hash of the document's exact
#'   text. Anything else is refused before sending.
#'
#' @return Parsed API response list as from `verdifax_get_policy()`, with
#'   `document`, the exact text.
#'
#' @export
verdifax_get_account_policy <- function(client, document_hash) {
  .perform(.get(client, .policy_path(document_hash, base = .ACCOUNT_POLICIES_PATH)))
}

#' Show which rule of an account policy would fire on sample inputs.
#'
#' Calls `POST /account/policies/test`, with the same body and response as
#' `verdifax_test_policy()`. It seals nothing. Give exactly one of
#' `document` and `document_hash`; anything else is refused before sending.
#'
#' @inheritParams verdifax_get_account
#' @inheritParams verdifax_test_policy
#' @param document_hash Optional 64-char lowercase hex hash of a document
#'   already uploaded for the account.
#'
#' @return Parsed API response list with `ok`, `sealed` (always `FALSE`),
#'   `outcome`, `fired_rule_id` and `reason_code`.
#'
#' @export
verdifax_test_account_policy <- function(client, inputs, document = NULL, document_hash = NULL) {
  .test_policy_at(
    client, .ACCOUNT_POLICIES_PATH, "verdifax_test_account_policy",
    inputs, document, document_hash
  )
}

#' The chain of the account's policy changes, oldest first.
#'
#' Calls `GET /account/policies/history`. Save the text to a file and check
#' it with `verdifax-verify --policy-history FILE`. It is not parsed, so what
#' you save is what the server sent.
#'
#' @inheritParams verdifax_get_account
#'
#' @return The exact JSON text the server sent, a list of change records,
#'   as a single string.
#'
#' @export
verdifax_get_account_policy_history <- function(client) {
  .get_body_text(client, paste0(.ACCOUNT_POLICIES_PATH, "/history"))
}

#' Make a stored document the account's policy in force.
#'
#' Reads `verdifax_list_account_policies()` for `chain_id` (for example
#' `"account-7"`) and `newest_activation_hash`, then calls
#' `POST /account/policies/{document_hash}/activate` naming that newest
#' change, signed as `verdifax_activate_policy()` signs: the client's
#' request key signs the change over the account's chain, the document and
#' the previous change. The server refuses an unsigned change to an
#' account's policy, so a client without a `signing_key` is refused before
#' any request. Register the key first with
#' `verdifax_register_account_request_key()`.
#'
#' Rolling back is activating an earlier document: it is one more change in
#' the chain, so the change it undoes stays on the record. An HTTP 409 means
#' the chain moved because another change came first, or the document is
#' not yet effective; the call stops with the server's message and is not
#' retried.
#'
#' @inheritParams verdifax_get_account_policy
#' @param client A client handle from `verdifax_client()`, holding the
#'   account's owner key as `api_key` and constructed with the `signing_key`
#'   registered as its request key.
#'
#' @return The `activation` of the response: the change record.
#'
#' @export
verdifax_activate_account_policy <- function(client, document_hash) {
  .activate_policy_at(
    client, .ACCOUNT_POLICIES_PATH, document_hash, verdifax_list_account_policies,
    signature_required = .ACCOUNT_ACTIVATION_UNSIGNED
  )
}


# ── Admin ───────────────────────────────────────────────────────────────────

#' Create an account and its first owner key.
#'
#' Calls `POST /admin/accounts` with an admin key. The owner key creates the
#' account's member keys with `verdifax_create_account_key()`; an admin can
#' also add one with `verdifax_admin_create_key()` and its `account_id`. The
#' account number is a label Verdifax assigned, not a verified company
#' identity.
#'
#' @inheritParams verdifax_health
#' @param name The account's name, a single non-empty string.
#' @param tier Optional `"trial"` or `"production"`. The server defaults to
#'   `"trial"`.
#' @param expires_at Optional expiry of the owner key, an RFC 3339 time or a
#'   `YYYY-MM-DD` date.
#'
#' @return Parsed API response list with `ok`, `account`, as
#'   `verdifax_get_account()` returns it, and `owner_key`, as
#'   `verdifax_create_account_key()` returns a key, with `owner` set to
#'   `TRUE`. It holds the owner key's secret once.
#'
#' @export
verdifax_admin_create_account <- function(client, name, tier = NULL, expires_at = NULL) {
  body <- list(name = .account_string(name, "name", required = TRUE))
  body$tier <- .account_string(tier, "tier")
  body$expires_at <- .account_string(expires_at, "expires_at")
  .send(client, "POST", .ADMIN_ACCOUNTS_PATH, body)
}

#' List every account with its key counts.
#'
#' Calls `GET /admin/accounts` with an admin key.
#'
#' @inheritParams verdifax_health
#'
#' @return A list of accounts, each as `verdifax_get_account()` returns it.
#'
#' @export
verdifax_admin_list_accounts <- function(client) {
  .perform(.get(client, .ADMIN_ACCOUNTS_PATH))[["accounts"]]
}

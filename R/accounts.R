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
.ACCOUNT_SETTINGS_PATH <- "/account/settings"
# Each owner setting's route name and the change name its signature covers.
.OWNER_SETTING_CHANGES <- c(
  "owner-replacement" = "setting.owner_replacement",
  "verdifax-deletion" = "setting.verdifax_deletion"
)
.OWNER_SETTING_VALUES <- c("allowed", "blocked")
.RUN_DELETED_CHANGE <- "run.deleted"
.OWNER_CHANGE_UNSIGNED <- paste0(
  "an owner setting or deletion must be signed by the owner key's request key: ",
  "construct the client with signing_key and register it with ",
  "verdifax_register_account_request_key(), so no change was asked for"
)
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
#'   and `owner_keys` (counts of keys not revoked), `chain_id`, the chain
#'   of the account's policy changes, and the owner's two settings,
#'   `owner_replacement` and `verdifax_deletion`, each `"allowed"` or
#'   `"blocked"`, as `verdifax_set_account_setting()` sets them.
#'
#' @export
verdifax_get_account <- function(client) {
  .perform(.get(client, .ACCOUNT_PATH))
}

#' Choose the second time zone on the account's audit reports.
#'
#' Calls `PUT /account/time-zone` with the account's owner key. Every audit
#' report shows times in UTC and one more zone: pass an IANA zone such as
#' `"Europe/London"`, `"none"` for UTC alone, or `""` for the zone of the
#' server's region, which an account that never chose sees. It changes how
#' times are displayed, never a sealed value.
#'
#' @inheritParams verdifax_get_account
#' @param time_zone A single string, at most 64 characters.
#'
#' @return Parsed API response list with `ok`, `account_id` and `time_zone`.
#'
#' @export
verdifax_set_account_time_zone <- function(client, time_zone) {
  if (!is.character(time_zone) || length(time_zone) != 1L || is.na(time_zone) || nchar(time_zone) > 64L) {
    stop("time_zone must be a single string of at most 64 characters", call. = FALSE)
  }
  .send(client, "PUT", paste0(.ACCOUNT_PATH, "/time-zone"), list(time_zone = time_zone))
}


# The account label the owner's signature covers: the one given, or the
# account_id GET /account returns. A label given is checked before any
# request; one read from the server is checked before the change is asked for.
.owner_account_label <- function(client, account_id) {
  read <- is.null(account_id)
  label <- if (read) verdifax_get_account(client)[["account_id"]] else account_id
  if (!is.character(label) || length(label) != 1 || is.na(label) ||
      !grepl(.SIGNAL_ACCOUNT_PATTERN, label)) {
    stop(
      if (read) {
        "the server did not return account_id, so the change cannot be signed and was not asked for"
      } else {
        "account_id must be the account's label, for example \"account-7\""
      },
      call. = FALSE
    )
  }
  as.vector(label)
}

# The owner signature a returned record seals is the one sent, under the
# client's own request key.
.same_owner_signature <- function(got, sent, signer) {
  is.list(got) &&
    identical(got[["signature"]], sent$signature) &&
    identical(got[["signed_at"]], sent$signed_at) &&
    identical(got[["nonce"]], sent$nonce) &&
    identical(got[["public_key"]], .base64(signer$public_key))
}

# The account change the server returns must carry the action, value, owner
# decision and owner signature that were sent, or the call stops. NULL means
# the value was already set and nothing was sealed.
.check_returned_account_change <- function(result, change, body, signer) {
  record <- result[["account_change"]]
  if (is.null(record)) {
    return(result)
  }
  same <- is.list(record) &&
    identical(record[["action"]], change) &&
    identical(record[["value"]], body$value) &&
    identical(record[["decided_by"]], "owner") &&
    .same_owner_signature(record[["owner_signature"]], body$owner_signature, signer)
  if (!same) {
    stop(
      "the server returned an account change that does not carry the action, value, ",
      "decided_by owner and owner_signature that were sent",
      call. = FALSE
    )
  }
  result
}

# The tombstone the server returns must carry the run, record hash, owner
# decision and owner signature that were sent, or the call stops.
.check_returned_run_deletion <- function(result, run_id, body, signer) {
  record <- result[["run_deletion"]]
  got_id <- if (is.list(record)) record[["run_id"]]
  same <- is.list(record) &&
    is.numeric(got_id) && length(got_id) == 1 && !is.na(got_id) &&
    identical(format(got_id, scientific = FALSE, trim = TRUE), run_id) &&
    identical(record[["record_hash"]], body$record_hash) &&
    identical(record[["decided_by"]], "owner") &&
    .same_owner_signature(record[["owner_signature"]], body$owner_signature, signer)
  if (!same) {
    stop(
      "the server returned a run deletion that does not carry the run_id, record_hash, ",
      "decided_by owner and owner_signature that were sent",
      call. = FALSE
    )
  }
  result
}

# A label the caller gives, checked before anything is sent.
.check_owner_account_label <- function(account_id) {
  if (!is.null(account_id) && (!is.character(account_id) || length(account_id) != 1 ||
      is.na(account_id) || !grepl(.SIGNAL_ACCOUNT_PATTERN, account_id))) {
    stop("account_id must be the account's label, for example \"account-7\"", call. = FALSE)
  }
  invisible(TRUE)
}

#' Allow or block a change Verdifax could make to the account.
#'
#' Calls `PUT /account/settings/{setting}` with the account's owner key.
#' `"owner-replacement"` decides whether Verdifax may replace a lost owner
#' key, and `"verdifax-deletion"` whether Verdifax may delete the account's
#' records. While a setting is `"blocked"`, the server refuses that change,
#' and `verdifax-verify --signals` fails a feed that shows one after the
#' block.
#'
#' The client's request key, registered with
#' `verdifax_register_account_request_key()`, signs the change, over
#' `verdifax.owner-change-signature.v1`, the account's label, the change
#' (`setting.owner_replacement` or `setting.verdifax_deletion`), the value,
#' the time and a fresh nonce. Verdifax never holds that key, so it cannot
#' make an owner's change. The server refuses an unsigned change, so a
#' client without a `signing_key` is refused before any request. The change
#' is sealed as an account change, anchored on the public log and placed in
#' the account's signal feed as an `account.changed` event.
#'
#' @param client A client handle from `verdifax_client()`, holding the
#'   account's owner key as `api_key` and constructed with the `signing_key`
#'   registered as its request key.
#' @param setting `"owner-replacement"` or `"verdifax-deletion"`. Anything
#'   else is refused before sending.
#' @param value `"allowed"` or `"blocked"`. Anything else is refused before
#'   sending.
#' @param account_id Optional account label the signature covers, for
#'   example `"account-7"`. When `NULL`, it is read from
#'   `verdifax_get_account()` first.
#'
#' @return Parsed API response list with `ok`, `setting`, `value` and
#'   `account_change`, the sealed record (`format`, `action`, `decided_by`,
#'   `value`, `changed_at`, `owner_signature`, `signal`,
#'   `account_change_hash`, `anchor`), or `NULL` when the setting already
#'   had that value, so nothing changed and nothing was sealed. The call
#'   stops with an error when a returned record does not carry the change,
#'   the value, `decided_by` `"owner"` and the `owner_signature` that were
#'   sent, with `public_key` the client's request key.
#'
#' @export
verdifax_set_account_setting <- function(client, setting, value, account_id = NULL) {
  if (!is.character(setting) || length(setting) != 1 || is.na(setting) ||
      !setting %in% names(.OWNER_SETTING_CHANGES)) {
    stop("setting must be \"owner-replacement\" or \"verdifax-deletion\"", call. = FALSE)
  }
  if (!is.character(value) || length(value) != 1 || is.na(value) ||
      !value %in% .OWNER_SETTING_VALUES) {
    stop("value must be \"allowed\" or \"blocked\"", call. = FALSE)
  }
  .check_owner_account_label(account_id)
  signer <- .active_signer(client)
  if (is.null(signer)) {
    stop(.OWNER_CHANGE_UNSIGNED, call. = FALSE)
  }
  account <- .owner_account_label(client, account_id)
  setting <- as.vector(setting)
  value <- as.vector(value)
  change <- .OWNER_SETTING_CHANGES[[setting]]
  body <- list(value = value, owner_signature = .owner_signature(signer, account, change, value))
  result <- .send(client, "PUT", paste0(.ACCOUNT_SETTINGS_PATH, "/", setting), body)
  .check_returned_account_change(result, change, body, signer)
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
#' @param lenient `TRUE` asks the server to ignore or replace a value it
#'   cannot read instead of refusing the request with HTTP 400.
#'
#' @return Parsed API response list with `total`, `limit`, `offset` and
#'   `runs`, as from `verdifax_list_runs()`. Each run holds `api_key_id`,
#'   the id of the account's key that requested it.
#'
#' @export
verdifax_list_account_runs <- function(client, limit = NULL, offset = NULL, lenient = FALSE) {
  .perform(.get(client, .ACCOUNT_RUNS_PATH, .query(limit = limit, offset = offset, lenient = if (isTRUE(lenient)) "1" else NULL)))
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
#'   `account_policy_documents` and `account_policy_history`, and
#'   `signoffs`, the account's whole chain of sign-offs, oldest first, as
#'   `verdifax_get_signoff_history()` returns it. Each row holds
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


#' Delete one of the account's records, signed by the owner.
#'
#' Calls `POST /account/runs/{id}/delete` with the account's owner key. The
#' record may have been made by any key of the account. Name the record you
#' mean to delete by its hash: a completed run's `record_hash` from
#' `verdifax_attest()`, or a stopped run's receipt hash. The server answers
#' HTTP 409 when it is not this run's record hash, and when the record is
#' public: withdraw it first with `verdifax_unpublish_run()`.
#'
#' The client's request key signs the deletion as
#' `verdifax_set_account_setting()` signs a setting, with the change
#' `run.deleted` and the subject `"<run_id>:<record_hash>"`. A client
#' without a `signing_key` is refused before any request. The deletion is
#' sealed as a tombstone that names the record, anchored on the public log
#' and placed in the account's signal feed as a `run.deleted` event, so the
#' feed and the public log still account for the record once it is gone.
#'
#' @inheritParams verdifax_set_account_setting
#' @param run_id The run's id, a positive whole number.
#' @param record_hash 64-char lowercase hex hash of the record to delete.
#'   Anything else is refused before sending.
#'
#' @return Parsed API response list with `ok`, `run_id`, `deleted` and
#'   `run_deletion`, the sealed tombstone (`format`, `decided_by`, `run_id`,
#'   `record_hash`, `job_id`, `step_id`, `changed_at`, `owner_signature`,
#'   `signal`, `deletion_hash`, `anchor`). The call stops with an error
#'   when the tombstone does not carry the `run_id`, the `record_hash`,
#'   `decided_by` `"owner"` and the `owner_signature` that were sent, with
#'   `public_key` the client's request key.
#'
#' @export
verdifax_delete_run <- function(client, run_id, record_hash, account_id = NULL) {
  id <- .require_id(run_id, "run_id")
  verdifax_validate_hex64(record_hash, "record_hash")
  .check_owner_account_label(account_id)
  signer <- .active_signer(client)
  if (is.null(signer)) {
    stop(.OWNER_CHANGE_UNSIGNED, call. = FALSE)
  }
  account <- .owner_account_label(client, account_id)
  record_hash <- as.vector(record_hash)
  body <- list(
    record_hash = record_hash,
    owner_signature = .owner_signature(
      signer, account, .RUN_DELETED_CHANGE, paste0(id, ":", record_hash)
    )
  )
  result <- .send(client, "POST", paste0(.ACCOUNT_RUNS_PATH, "/", id, "/delete"), body)
  .check_returned_run_deletion(result, id, body, signer)
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
verdifax_test_account_policy <- function(client, inputs, document = NULL, document_hash = NULL,
                                         ai_output_declared = FALSE) {
  .test_policy_at(
    client, .ACCOUNT_POLICIES_PATH, "verdifax_test_account_policy",
    inputs, document, document_hash, ai_output_declared
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

#' Delete a record as Verdifax's decision.
#'
#' Calls `POST /admin/runs/{id}/delete` with an admin key. The deletion is
#' sealed as a tombstone in the feed of the record's account, with
#' `decided_by` `verdifax_admin`, and anchored on the public log. The
#' server refuses it with HTTP 409 while the account's owner blocks
#' Verdifax deletion, for a public record, which is withdrawn first, and
#' for a run that belongs to no account.
#'
#' @inheritParams verdifax_health
#' @param run_id The run's id, a positive whole number.
#'
#' @return Parsed API response list with `ok`, `run_id`, `deleted` and
#'   `run_deletion`, as `verdifax_delete_run()` returns them, with no
#'   `owner_signature`.
#'
#' @export
verdifax_admin_delete_run <- function(client, run_id) {
  .send(client, "POST", paste0("/admin/runs/", .require_id(run_id, "run_id"), "/delete"))
}

#' Start the replacement of an account's lost owner key.
#'
#' Calls `POST /admin/accounts/{id}/owner-key/replace` with an admin key, on
#' the owner's written request. The server seals the request in the
#' account's feed as an `account.changed` event and emails a one-time link,
#' valid for 72 hours, to the address of the access request that made the
#' account. The new owner key is made when the owner opens the link, so
#' Verdifax never sees it, and the response holds neither the link nor a
#' key. The server refuses it with HTTP 409 while the owner blocks owner-key
#' replacement, and for an account with no address on file.
#'
#' @inheritParams verdifax_health
#' @param account_id The account's numeric id, a positive whole number, as
#'   `verdifax_admin_list_accounts()` lists it in `id`.
#'
#' @return Parsed API response list with `ok`, `account_id` (the label, such
#'   as `"account-7"`), `claim_expires`, `account_change`, the sealed record,
#'   and `email`, the result of sending the link.
#'
#' @export
verdifax_admin_replace_owner_key <- function(client, account_id) {
  .send(
    client, "POST",
    paste0(.ADMIN_ACCOUNTS_PATH, "/", .require_id(account_id, "account_id"), "/owner-key/replace")
  )
}

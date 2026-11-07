# ----------------------------------------------------------------------------
# verdifax, customer sign-off on results
# ----------------------------------------------------------------------------
#
# The account's owner registers approver keys. An approver signs a decision,
# approve or reject, on one exact result on this machine with the approver
# key, and any key in the account submits it. The server checks it, links it
# to the account's previous sign-off and logs it on the public log.
#
# A sign-off shows that the holder of a registered approver key signed that
# decision on that exact result, and that Verdifax logged it. It does not
# show the review was careful, the result right, or who the person is: a key
# is not an identity. It gates nothing on its own. Verdifax did not review
# the result. The approver key and the note's text are never sent.

.SIGNOFF_FORM <- "verdifax.signoff.v1"
.APPROVER_KEY_PROOF_FORM <- "verdifax.approver-key.v1"
.APPROVERS_PATH <- "/account/approvers"
.SIGNOFF_KINDS <- c("record", "receipt", "job")
.SIGNOFF_DECISIONS <- c("approve", "reject")
.SIGNOFF_TARGET_FIELDS <- c("kind", "run_id", "digest", "job_id")
.APPROVER_NAME_MAX_BYTES <- 200L
.SIGNOFF_CHAIN_PATTERN <- "^account-[1-9][0-9]{0,18}$"
# The largest whole number a double holds exactly, so the run id signed is
# the run id sent.
.SIGNOFF_MAX_RUN_ID <- 2^53 - 1


# ── Input checks ────────────────────────────────────────────────────────────

# The member route, or with as_owner the owner key's /account route.
.signoff_base <- function(as_owner) {
  if (!is.logical(as_owner) || length(as_owner) != 1 || is.na(as_owner)) {
    stop("as_owner must be TRUE or FALSE", call. = FALSE)
  }
  if (as_owner) .ACCOUNT_PATH else ""
}

# The approver's signer. The key stays on this machine.
.approver_signer <- function(approver_key) {
  if (!is.raw(approver_key) || length(approver_key) != .SIGNING_KEY_BYTES) {
    stop(
      "approver_key must be the 32 raw bytes of the approver's Ed25519 private key",
      call. = FALSE
    )
  }
  .request_signer(approver_key)
}

# The server refuses an approver key that is a request key in the account,
# so the client's own request key is refused here before anything is sent.
# `public_key` is the approver's raw public key.
.refuse_request_key_as_approver <- function(client, public_key) {
  signer <- .active_signer(client)
  if (!is.null(signer) && identical(signer$public_key, public_key)) {
    stop(
      "approver_key is this client's request key; an approver key must be a different key",
      call. = FALSE
    )
  }
  invisible(TRUE)
}

.approver_name <- function(name) {
  if (!is.character(name) || length(name) != 1 || is.na(name)) {
    stop("name is required, a single string", call. = FALSE)
  }
  text <- enc2utf8(as.vector(name))
  if (!validUTF8(text)) {
    stop("name is not valid UTF-8", call. = FALSE)
  }
  trimmed <- trimws(text)
  if (!nzchar(trimmed) || nchar(trimmed, type = "bytes") > .APPROVER_NAME_MAX_BYTES) {
    stop("name is required, at most ", .APPROVER_NAME_MAX_BYTES, " bytes", call. = FALSE)
  }
  text
}

# Base64 that decodes to exactly `bytes` bytes, as raw, or NULL.
.base64_exact <- function(value, bytes) {
  if (!is.character(value) || length(value) != 1 || is.na(value) ||
      !grepl("^[A-Za-z0-9+/]+={0,2}$", value)) {
    return(NULL)
  }
  raw <- tryCatch(jsonlite::base64_dec(value), error = function(e) NULL)
  if (length(raw) != bytes || !identical(.base64(raw), value)) NULL else raw
}

# A ready-made proof, from verdifax_approver_key_proof() on the approver's
# machine, checked here as the server checks it, so one that does not verify
# is never sent.
.checked_approver_proof <- function(proof) {
  if (!is.list(proof) || length(proof) != 2 || is.null(names(proof)) ||
      !setequal(names(proof), c("public_key", "proof"))) {
    stop(
      "approver must be the approver's 32-byte signing key, or the list with public_key ",
      "and proof that verdifax_approver_key_proof() returns",
      call. = FALSE
    )
  }
  public_key <- .base64_exact(proof[["public_key"]], 32L)
  signature <- .base64_exact(proof[["proof"]], 64L)
  if (is.null(public_key) || is.null(signature)) {
    stop("approver$public_key and approver$proof must be a base64 Ed25519 key and signature",
      call. = FALSE)
  }
  .require_sodium()
  verified <- tryCatch(
    sodium::sig_verify(.approver_proof_preimage(proof[["public_key"]]), signature, public_key),
    error = function(e) FALSE
  )
  if (!isTRUE(verified)) {
    stop(
      "approver$proof does not verify: it must be the approver key's signature over ",
      "verdifax.approver-key.v1, a zero byte and the base64 key",
      call. = FALSE
    )
  }
  list(public_key = as.vector(proof[["public_key"]]), proof = as.vector(proof[["proof"]]),
       raw_public_key = public_key)
}

# The target as sent, in the order the server reads it. A field the server
# does not know is refused, because the server refuses the whole body.
.signoff_target <- function(target) {
  if (!is.list(target) || length(target) == 0 ||
      is.null(names(target)) || any(!nzchar(names(target)))) {
    stop(
      "target must be a named list with kind, run_id and digest, and job_id for a job",
      call. = FALSE
    )
  }
  if (anyDuplicated(names(target)) > 0) {
    stop("target names a field twice", call. = FALSE)
  }
  unknown <- setdiff(names(target), .SIGNOFF_TARGET_FIELDS)
  if (length(unknown) > 0) {
    stop("target has an unknown field: ", paste(unknown, collapse = ", "), call. = FALSE)
  }
  kind <- target[["kind"]]
  if (!is.character(kind) || length(kind) != 1 || is.na(kind) || !kind %in% .SIGNOFF_KINDS) {
    stop("target$kind must be one of ", paste(.SIGNOFF_KINDS, collapse = ", "), call. = FALSE)
  }
  run_id <- target[["run_id"]]
  valid_id <- is.numeric(run_id) && length(run_id) == 1 && !is.na(run_id) &&
    is.finite(run_id) && run_id > 0 && run_id == floor(run_id) && run_id <= .SIGNOFF_MAX_RUN_ID
  if (!valid_id) {
    stop("target$run_id must be a positive whole number", call. = FALSE)
  }
  verdifax_validate_hex64(target[["digest"]], "target$digest")
  job_id <- target[["job_id"]]
  if (kind == "job") {
    .check_job_name(job_id, "target$job_id")
  } else if (!is.null(job_id) && !identical(as.vector(job_id), "")) {
    stop("target$job_id is for a job target only", call. = FALSE)
  }
  out <- list(kind = as.vector(kind), run_id = as.vector(run_id), digest = as.vector(target[["digest"]]))
  if (kind == "job") {
    out$job_id <- as.vector(job_id)
  }
  out
}

.signoff_decision <- function(decision) {
  if (!is.character(decision) || length(decision) != 1 || is.na(decision) ||
      !decision %in% .SIGNOFF_DECISIONS) {
    stop("decision must be approve or reject", call. = FALSE)
  }
  as.vector(decision)
}

# The SHA-256 of the note's UTF-8 text, or the empty string for no note.
# Only the hash is sent. An empty note is refused: NULL is no note.
.signoff_note_hash <- function(note) {
  if (is.null(note)) {
    return("")
  }
  if (!is.character(note) || length(note) != 1 || is.na(note) || !nzchar(note)) {
    stop("note must be a non-empty single string, or NULL for no note", call. = FALSE)
  }
  text <- enc2utf8(as.vector(note))
  if (!validUTF8(text)) {
    stop("note is not valid UTF-8", call. = FALSE)
  }
  .sha256_hex(text)
}

.signoff_note_hash_field <- function(note_hash) {
  if (!identical(note_hash, "")) {
    verdifax_validate_hex64(note_hash, "note_hash")
  }
  invisible(TRUE)
}


# The target the server recorded is the one sent: the same kind, run, digest
# and job.
.same_signoff_target <- function(got, sent) {
  run_id <- if (is.list(got)) got[["run_id"]]
  is.list(got) && identical(got[["kind"]], sent$kind) &&
    is.numeric(run_id) && length(run_id) == 1 && !is.na(run_id) && run_id == sent$run_id &&
    identical(got[["digest"]], sent$digest) &&
    identical(got[["job_id"]] %||% "", sent$job_id %||% "")
}

# The record the server returns must carry the signature, approver key,
# decision, place in the chain and target that were sent, or the call stops.
.check_returned_signoff <- function(record, body) {
  same <- is.list(record) &&
    identical(record[["signature"]], body$signature) &&
    identical(record[["approver_key"]], body$approver_key) &&
    identical(record[["decision"]], body$decision) &&
    identical(record[["previous_signoff_hash"]], body$previous_signoff_hash) &&
    .same_signoff_target(record[["target"]], body$target)
  if (!same) {
    stop(
      "the server returned a sign-off record that does not carry the signature, approver_key, ",
      "decision, previous_signoff_hash and target that were sent",
      call. = FALSE
    )
  }
  record
}


# ── Signing ─────────────────────────────────────────────────────────────────

.approver_proof_preimage <- function(public_key) {
  .join_with_zero(list(.APPROVER_KEY_PROOF_FORM, public_key))
}

.approver_proof <- function(signer) {
  public_key <- .base64(signer$public_key)
  list(public_key = public_key, proof = .base64(signer$sign(.approver_proof_preimage(public_key))))
}

# The body of POST /signoffs: the approver's signed decision. `target` is
# the checked target from .signoff_target().
.signoff_body <- function(signer, chain_id, previous_signoff_hash, target, decision,
                          note_hash, signed_at = NULL, nonce = NULL) {
  signed_at <- signed_at %||% .signing_time()
  nonce <- nonce %||% .signing_nonce()
  preimage <- verdifax_signoff_preimage(
    chain_id, previous_signoff_hash, target, decision, note_hash, signed_at, nonce
  )
  body <- list(previous_signoff_hash = previous_signoff_hash, target = target, decision = decision)
  if (nzchar(note_hash)) {
    body$note_hash <- note_hash
  }
  body$approver_key <- .base64(signer$public_key)
  body$signature <- .base64(signer$sign(preimage))
  body$signed_at <- signed_at
  body$nonce <- nonce
  body
}

#' The bytes an approver key signs for a sign-off.
#'
#' @param chain_id The account's chain of sign-offs, as
#'   `verdifax_get_newest_signoff()` returns it, for example `"account-7"`.
#' @param previous_signoff_hash 64-char lowercase hex hash of the account's
#'   newest sign-off, or 64 zeros when there is none yet.
#' @param target The exact result, a named list: `kind` (`"record"`,
#'   `"receipt"` or `"job"`), `run_id`, `digest` and, for a job only,
#'   `job_id`. See `verdifax_sign_off()`.
#' @param decision `"approve"` or `"reject"`.
#' @param note_hash 64-char lowercase hex SHA-256 of the note's text, or
#'   `""` for no note.
#' @param signed_at The RFC 3339 UTC time.
#' @param nonce The nonce as 32 lowercase hex characters.
#'
#' @return A raw vector: `verdifax.signoff.v1`, `chain_id`,
#'   `previous_signoff_hash`, the target's `kind`, `run_id`, `digest` and
#'   `job_id` (empty unless a job), `decision`, `note_hash`, `signed_at` and
#'   `nonce`, as UTF-8, joined by single zero bytes.
#'
#' @export
verdifax_signoff_preimage <- function(chain_id, previous_signoff_hash, target, decision,
                                      note_hash, signed_at, nonce) {
  .check_preimage_field(chain_id, "chain_id")
  verdifax_validate_hex64(previous_signoff_hash, "previous_signoff_hash")
  target <- .signoff_target(target)
  decision <- .signoff_decision(decision)
  .check_preimage_field(note_hash, "note_hash")
  .signoff_note_hash_field(note_hash)
  .check_preimage_field(signed_at, "signed_at")
  .check_preimage_field(nonce, "nonce")
  .join_with_zero(list(
    .SIGNOFF_FORM, chain_id, previous_signoff_hash, target$kind,
    format(target$run_id, scientific = FALSE, trim = TRUE), target$digest,
    target$job_id %||% "", decision, note_hash, signed_at, nonce
  ))
}

#' Build an approver key's proof without sending anything.
#'
#' The proof is the approver key's Ed25519 signature over
#' `verdifax.approver-key.v1`, a zero byte and the base64 public key. It shows
#' the key's holder has the private key. `verdifax_register_approver()`
#' takes the list this returns, so the approver can run this on their own
#' machine and the owner never holds the approver's private key. Needs the
#' `sodium` package.
#'
#' @param approver_key The 32 raw bytes of the approver's Ed25519 private
#'   key, from `verdifax_generate_request_key()`. It is never sent.
#'
#' @return A list with `public_key` and `proof`, both base64.
#'
#' @export
verdifax_approver_key_proof <- function(approver_key) {
  .approver_proof(.approver_signer(approver_key))
}


# ── Approver keys ───────────────────────────────────────────────────────────

#' Register an approver key to the owner key's account.
#'
#' Calls `POST /account/approvers` with the approver's public key, a name and
#' the proof that its holder has the private key. The owner never has to
#' hold the approver's private key: the approver runs
#' `verdifax_approver_key_proof()` on their own machine and hands over the
#' list it returns, and this function checks the proof here and refuses one
#' that does not verify before sending. Given the approver's private key
#' instead, it makes the proof here. The private key is never sent.
#'
#' An approver key is never a request key in the same account: the server
#' refuses one with HTTP 409, and the client's own `signing_key` is refused
#' before sending.
#'
#' @param client A client handle from `verdifax_client()`, holding the
#'   account's owner key as `api_key`.
#' @param approver Either the list with `public_key` and `proof` that
#'   `verdifax_approver_key_proof()` returns, or the 32 raw bytes of the
#'   approver's Ed25519 private key, from `verdifax_generate_request_key()`.
#'   Needs the `sodium` package.
#' @param name The approver's name, a single non-empty string of at most 200
#'   bytes. It is a label, not a verified identity.
#'
#' @return Parsed API response list with `ok`, `id`, `public_key`, `name`,
#'   `account_id`, `registered_at` and `revoked`.
#'
#' @export
verdifax_register_approver <- function(client, approver, name) {
  name <- .approver_name(name)
  if (is.raw(approver)) {
    signer <- .approver_signer(approver)
    proof <- .approver_proof(signer)
    public_key <- signer$public_key
  } else {
    proof <- .checked_approver_proof(approver)
    public_key <- proof$raw_public_key
  }
  .refuse_request_key_as_approver(client, public_key)
  body <- list(public_key = proof$public_key, name = name, proof = proof$proof)
  .send(client, "POST", .APPROVERS_PATH, body)
}

#' List the account's approver keys, revoked ones included.
#'
#' Calls `GET /account/approvers` with the account's owner key.
#'
#' @inheritParams verdifax_get_account
#'
#' @return Parsed API response list with `ok`, `account_id` and
#'   `approvers`. Each holds `id`, `public_key`, `name`, `account_id`,
#'   `registered_at`, `revoked` and, once revoked, `revoked_at`.
#'
#' @export
verdifax_list_approvers <- function(client) {
  .perform(.get(client, .APPROVERS_PATH))
}

#' Revoke one of the account's approver keys.
#'
#' Calls `DELETE /account/approvers/{id}`. The key's earlier sign-offs stay
#' on the record. An approver that is not active in this account answers
#' HTTP 404, and the call stops with the server's message.
#'
#' @inheritParams verdifax_get_account
#' @param approver_id The approver's `id`, a positive whole number.
#'
#' @return Parsed API response list with `ok`, `id` and `revoked`.
#'
#' @export
verdifax_revoke_approver <- function(client, approver_id) {
  .send(client, "DELETE", paste0(.APPROVERS_PATH, "/", .require_id(approver_id, "approver_id")))
}


# ── Sign-offs ───────────────────────────────────────────────────────────────

#' The account's chain of sign-offs and its newest sign-off.
#'
#' Calls `GET /signoffs/newest`, or with `as_owner = TRUE` the owner key's
#' `GET /account/signoffs/newest`. It is what an approver signs against.
#'
#' @param client A client handle from `verdifax_client()`, holding a member
#'   key of the account, or its owner key with `as_owner = TRUE`.
#' @param as_owner `TRUE` to use the owner key's `/account` route.
#'
#' @return Parsed API response list with `ok`, `chain_id` (for example
#'   `"account-7"`), `newest_signoff_hash` (64 zeros before the first
#'   sign-off) and `sequence`.
#'
#' @export
verdifax_get_newest_signoff <- function(client, as_owner = FALSE) {
  .perform(.get(client, paste0(.signoff_base(as_owner), "/signoffs/newest")))
}

#' Sign off on one exact result, as an approver.
#'
#' Checks every input, reads the account's chain and newest sign-off with
#' `verdifax_get_newest_signoff()`, hashes the note here, signs the decision
#' with `approver_key` and submits it with `POST /signoffs`, or with
#' `as_owner = TRUE` the owner key's `POST /account/signoffs`. Bad input is
#' refused before anything is sent. The approver key and the note's text
#' are never sent: only the public key, the signature and the note's
#' SHA-256.
#'
#' The target names the result by what its public-log entry covers:
#'
#' * a completed run's record: `kind = "record"`, its `run_id` and, as
#'   `digest`, the `anchored_digest` of the `bundle_anchor` in the text from
#'   `verdifax_get_run_artifacts()`, for example
#'   `jsonlite::fromJSON(text)$bundle_anchor$anchored_digest`;
#' * a refused or halted run's receipt: `kind = "receipt"`, its `run_id`
#'   and, as `digest`, the receipt's `hash`;
#' * a whole job: `kind = "job"`, the `run_id` of its final step, the
#'   `job_id`, and as `digest` the final step's record digest, read as for a
#'   record.
#'
#' A sign-off shows that the holder of a registered approver key signed
#' that decision on that exact result, and that Verdifax logged it on the
#' public log. It does not show the review was careful, the result right,
#' or who the person is: a key is not an identity. It gates nothing on its
#' own. A later sign-off on the same result supersedes the earlier one, and
#' nothing is deleted. Verdifax did not review the result.
#'
#' An HTTP 409 means the chain moved because another sign-off came first,
#' or the target is not a result of this account with that digest; the
#' call stops with the server's message and is not retried. The call also
#' stops with an error when the record the server returns does not carry
#' the signature, `approver_key`, `decision`, `previous_signoff_hash` and
#' `target` that were sent.
#'
#' @inheritParams verdifax_get_newest_signoff
#' @param target The exact result, a named list with `kind`, `run_id`,
#'   `digest` and, for a job only, `job_id`.
#' @param decision `"approve"` or `"reject"`.
#' @param approver_key The 32 raw bytes of the approver's Ed25519 private
#'   key, registered with `verdifax_register_approver()`. It must not be the
#'   client's own `signing_key`. Needs the `sodium` package.
#' @param note Optional note, a non-empty single string. Only its SHA-256 is
#'   sent, as `note_hash`. `NULL` is no note, and then `note_hash` is left
#'   out of the body. An empty string is refused.
#'
#' @return The `signoff` of the response: the sign-off record, with its
#'   `sequence`, `signoff_hash` and public-log `anchor`, once it is checked
#'   to carry what was sent.
#'
#' @export
verdifax_sign_off <- function(client, target, decision, approver_key, note = NULL,
                              as_owner = FALSE) {
  base <- .signoff_base(as_owner)
  target <- .signoff_target(target)
  decision <- .signoff_decision(decision)
  note_hash <- .signoff_note_hash(note)
  approver <- .approver_signer(approver_key)
  .refuse_request_key_as_approver(client, approver$public_key)
  state <- verdifax_get_newest_signoff(client, as_owner = as_owner)
  chain_id <- state[["chain_id"]]
  if (!is.character(chain_id) || length(chain_id) != 1 ||
      !grepl(.SIGNOFF_CHAIN_PATTERN, chain_id)) {
    stop("the server did not return chain_id, so nothing was signed", call. = FALSE)
  }
  previous <- state[["newest_signoff_hash"]]
  if (!is.character(previous) || length(previous) != 1 || !grepl("^[0-9a-f]{64}$", previous)) {
    stop("the server did not return newest_signoff_hash, so nothing was signed", call. = FALSE)
  }
  body <- .signoff_body(approver, chain_id, previous, target, decision, note_hash)
  record <- .send(client, "POST", paste0(base, "/signoffs"), body)[["signoff"]]
  .check_returned_signoff(record, body)
}

#' The sign-offs on one run, oldest first.
#'
#' Calls `GET /runs/{id}/signoffs` for a run this member key made, or with
#' `as_owner = TRUE` the owner key's `GET /account/runs/{id}/signoffs` for
#' any run of the account. The newest sign-off on a result is the decision
#' in force; the earlier ones stay on the record.
#'
#' Save the text to a file with `writeLines(text, path, sep = "")` and check
#' it with `verdifax-verify --signoff FILE` beside the run's record or
#' receipt. It is not parsed, so what you save is what the server sent.
#'
#' @inheritParams verdifax_get_newest_signoff
#' @param run_id The run's id, a positive whole number.
#'
#' @return The exact JSON text the server sent, a list of sign-off records,
#'   as a single string. Read it with `jsonlite::fromJSON()`. Each record
#'   holds `format`, `chain_id`, `sequence`, `previous_signoff_hash`,
#'   `target`, `decision`, `note_hash` when there was a note,
#'   `approver_key`, `signature`, `signed_at`, `nonce`, `recorded_at`,
#'   `signoff_hash` and `anchor`.
#'
#' @export
verdifax_get_signoffs <- function(client, run_id, as_owner = FALSE) {
  base <- .signoff_base(as_owner)
  .get_body_text(client, paste0(base, .run_path(run_id, "/signoffs")))
}

#' The account's whole chain of sign-offs, oldest first.
#'
#' Calls `GET /account/signoffs/history` with the account's owner key. Save
#' the text to a file and check it with
#' `verdifax-verify --signoff-history FILE`. It is not parsed, so what you
#' save is what the server sent.
#'
#' @inheritParams verdifax_get_account
#'
#' @return The exact JSON text the server sent, a list of sign-off records,
#'   as a single string. Read it with `jsonlite::fromJSON()`.
#'
#' @export
verdifax_get_signoff_history <- function(client) {
  .get_body_text(client, paste0(.ACCOUNT_PATH, "/signoffs/history"))
}

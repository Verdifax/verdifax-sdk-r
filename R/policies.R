# ----------------------------------------------------------------------------
# verdifax, customer policies and the policy_context checks
# ----------------------------------------------------------------------------
#
# A customer's policy is a document the customer writes. The server stores
# its exact text, and a run is decided under it once it is activated.
# Verdifax did not write, review or approve it.

.POLICY_CONTEXT_FIELDS <- c(
  "actor_type", "mfa_satisfied", "session_age_seconds",
  "object_type", "object_id", "classification", "data_quality"
)
.DATA_QUALITY_FIELDS <- c("source", "as_of", "checks")
.DATA_CHECK_FIELDS <- c("name", "result")
.DATA_CHECK_RESULTS <- c("pass", "fail", "warn")
.DATA_SOURCE_MAX_BYTES <- 200L
.DATA_CHECKS_MAX <- 50L
.DATA_CHECK_NAME_MAX_BYTES <- 100L
# The one form an as_of time may take, in ASCII digits, as the server checks
# it (tests/testthat/sdk-data-quality-vector.json). \z, not $, ends it: in a
# perl = TRUE pattern $ also matches before a final newline.
.AS_OF_SHAPE <- paste0(
  "^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})",
  "(\\.[0-9]{1,9})?(Z|[+-]([0-9]{2}):([0-9]{2}))\\z"
)
# The code points Go's strings.TrimSpace removes, which the server uses to
# find a blank check name. U+FEFF and U+001C to U+001F are not among them.
.GO_SPACES <- c(
  0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20, 0x85, 0xA0, 0x1680, 0x2000:0x200A,
  0x2028, 0x2029, 0x202F, 0x205F, 0x3000
)
.POLICY_ACTOR_TYPES <- c("agent", "user", "service", "system")
.POLICY_OBJECT_TYPES <- c("text", "transaction", "code", "data", "model", "file")
.POLICY_CLASSIFICATIONS <- c(
  "PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED", "TOP_SECRET", "TS_SCI"
)
.POLICY_OBJECT_ID_MAX_BYTES <- 256L
# The largest whole number a double holds exactly, so the number sent is
# the number given.
.POLICY_MAX_SESSION_AGE <- 2^53 - 1


# ── policy_context ──────────────────────────────────────────────────────────

.policy_choice <- function(value, name, choices) {
  if (!is.character(value) || length(value) != 1 || is.na(value) || !value %in% choices) {
    stop(
      "policy_context$", name, " must be one of ", paste(choices, collapse = ", "),
      call. = FALSE
    )
  }
  as.vector(value)
}

.policy_flag <- function(value, name) {
  if (!is.logical(value) || length(value) != 1 || is.na(value)) {
    stop("policy_context$", name, " must be TRUE or FALSE", call. = FALSE)
  }
  as.vector(value)
}

.policy_session_age <- function(value) {
  valid <- is.numeric(value) && length(value) == 1 && !is.na(value) && is.finite(value) &&
    value >= 0 && value == floor(value) && value <= .POLICY_MAX_SESSION_AGE
  if (!valid) {
    stop(
      "policy_context$session_age_seconds must be a whole number of seconds, not negative",
      call. = FALSE
    )
  }
  as.vector(value)
}

.policy_object_id <- function(value) {
  if (!is.character(value) || length(value) != 1 || is.na(value)) {
    stop("policy_context$object_id must be a single string", call. = FALSE)
  }
  text <- enc2utf8(as.vector(value))
  if (!validUTF8(text)) {
    stop("policy_context$object_id is not valid UTF-8", call. = FALSE)
  }
  if (nchar(text, type = "bytes") > .POLICY_OBJECT_ID_MAX_BYTES) {
    stop(
      "policy_context$object_id is longer than ", .POLICY_OBJECT_ID_MAX_BYTES, " bytes",
      call. = FALSE
    )
  }
  text
}

# Whether `value` is an as_of time the server accepts: the form above, a real
# calendar date and time, and an offset of at most 23:59.
.valid_as_of <- function(value) {
  shape <- regmatches(value, regexec(.AS_OF_SHAPE, value, perl = TRUE))[[1]]
  if (length(shape) == 0) {
    return(FALSE)
  }
  part <- as.integer(shape[2:7])
  year <- part[1]
  leap <- year %% 4 == 0 && (year %% 100 != 0 || year %% 400 == 0)
  month_days <- c(31, if (leap) 29 else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)
  if (part[2] < 1 || part[2] > 12 || part[3] < 1 || part[3] > month_days[part[2]]) {
    return(FALSE)
  }
  if (part[4] > 23 || part[5] > 59 || part[6] > 59) {
    return(FALSE)
  }
  if (nzchar(shape[10]) && (as.integer(shape[10]) > 23 || as.integer(shape[11]) > 59)) {
    return(FALSE)
  }
  TRUE
}

.data_text <- function(value, what) {
  if (!is.character(value) || length(value) != 1 || is.na(value)) {
    stop("policy_context$data_quality$", what, " must be a single string", call. = FALSE)
  }
  text <- enc2utf8(as.vector(value))
  if (!validUTF8(text)) {
    stop("policy_context$data_quality$", what, " is not valid UTF-8", call. = FALSE)
  }
  text
}

.named_fields <- function(value, known, what) {
  if (!is.list(value) || (length(value) > 0 &&
      (is.null(names(value)) || any(!nzchar(names(value)))))) {
    stop(what, " must be a named list", call. = FALSE)
  }
  unknown <- setdiff(names(value), known)
  if (length(unknown) > 0) {
    stop(what, " has an unknown field: ", paste(unknown, collapse = ", "), call. = FALSE)
  }
  if (anyDuplicated(names(value)) > 0) {
    stop(what, " names a field twice", call. = FALSE)
  }
  value[!vapply(value, is.null, logical(1))]
}

# A data_quality declaration, checked the way the server checks it: where
# the data came from, the time it describes and the checks run on it.
.policy_data_quality <- function(value) {
  value <- .named_fields(value, .DATA_QUALITY_FIELDS, "policy_context$data_quality")
  block <- list()
  if (!is.null(value$source)) {
    source <- .data_text(value$source, "source")
    if (nchar(source, type = "bytes") > .DATA_SOURCE_MAX_BYTES) {
      stop(
        "policy_context$data_quality$source is longer than ", .DATA_SOURCE_MAX_BYTES, " bytes",
        call. = FALSE
      )
    }
    block$source <- source
  }
  if (!is.null(value$as_of)) {
    as_of <- .data_text(value$as_of, "as_of")
    if (nzchar(as_of) && !.valid_as_of(as_of)) {
      stop(
        "policy_context$data_quality$as_of must be a time of the form ",
        "2026-11-11T09:00:00Z or 2026-11-11T09:00:00+05:30",
        call. = FALSE
      )
    }
    block$as_of <- as_of
  }
  if (!is.null(value$checks)) {
    checks <- value$checks
    if (!is.list(checks) || !is.null(names(checks))) {
      stop(
        "policy_context$data_quality$checks must be an unnamed list of checks",
        call. = FALSE
      )
    }
    if (length(checks) > .DATA_CHECKS_MAX) {
      stop(
        "policy_context$data_quality names more than ", .DATA_CHECKS_MAX, " checks",
        call. = FALSE
      )
    }
    seen <- character(0)
    block$checks <- lapply(checks, function(check) {
      check <- .named_fields(check, .DATA_CHECK_FIELDS, "each policy_context$data_quality check")
      name <- check$name
      named <- is.character(name) && length(name) == 1 && !is.na(name) &&
        validUTF8(enc2utf8(name))
      if (named) {
        name <- enc2utf8(as.vector(name))
        named <- !all(utf8ToInt(name) %in% .GO_SPACES) &&
          nchar(name, type = "bytes") <= .DATA_CHECK_NAME_MAX_BYTES && !name %in% seen
      }
      if (!named) {
        stop(
          "each policy_context$data_quality check needs a distinct name of at most ",
          .DATA_CHECK_NAME_MAX_BYTES, " bytes",
          call. = FALSE
        )
      }
      seen <<- c(seen, name)
      result <- check$result
      if (!is.character(result) || length(result) != 1 || is.na(result) ||
          !result %in% .DATA_CHECK_RESULTS) {
        stop(
          "policy_context$data_quality check ", name, " has a result that is not pass, fail or warn",
          call. = FALSE
        )
      }
      list(name = name, result = as.vector(result))
    })
  }
  block
}

# A value in actor_type, mfa_satisfied or session_age_seconds describes the
# attested actor. Without one the server refuses it, because the rules would
# read the zero value instead. FALSE and 0 are the zero values, so they pass.
.has_actor_values <- function(block) {
  !is.null(block$actor_type) || isTRUE(block$mfa_satisfied) ||
    (!is.null(block$session_age_seconds) && block$session_age_seconds != 0)
}

# The block as sent, or NULL when it holds nothing. An unknown field or a
# value no rule could read is refused, because the server would refuse it
# too and a rule on a dropped field would read its zero value. `attested` is
# the attested flag of the attested_context sent with it, as the server
# reads it.
.policy_context_block <- function(context, attested = FALSE) {
  if (!is.list(context) || (length(context) > 0 &&
      (is.null(names(context)) || any(!nzchar(names(context)))))) {
    stop("policy_context must be a named list", call. = FALSE)
  }
  unknown <- setdiff(names(context), .POLICY_CONTEXT_FIELDS)
  if (length(unknown) > 0) {
    stop(
      "policy_context has an unknown field: ", paste(unknown, collapse = ", "),
      call. = FALSE
    )
  }
  if (anyDuplicated(names(context)) > 0) {
    stop("policy_context names a field twice", call. = FALSE)
  }
  context <- context[!vapply(context, is.null, logical(1))]
  if (length(context) == 0) {
    return(NULL)
  }
  block <- list()
  for (name in intersect(.POLICY_CONTEXT_FIELDS, names(context))) {
    value <- context[[name]]
    block[[name]] <- switch(name,
      actor_type = .policy_choice(value, name, .POLICY_ACTOR_TYPES),
      object_type = .policy_choice(value, name, .POLICY_OBJECT_TYPES),
      classification = .policy_choice(value, name, .POLICY_CLASSIFICATIONS),
      mfa_satisfied = .policy_flag(value, name),
      session_age_seconds = .policy_session_age(value),
      object_id = .policy_object_id(value),
      data_quality = .policy_data_quality(value)
    )
  }
  if (.has_actor_values(block) && !isTRUE(attested)) {
    stop(
      "policy_context$actor_type, mfa_satisfied and session_age_seconds describe the ",
      "attested actor, so they need an attested_context with the actor",
      call. = FALSE
    )
  }
  block
}


# ── Requests ────────────────────────────────────────────────────────────────

# The exact text as one JSON string. A list or a vector of several strings
# is refused: serializing it would make text the caller never saw, with a
# different hash. as.vector() drops an I() wrapper, which would otherwise
# send the string as a one-item array.
.policy_document <- function(document) {
  if (!is.character(document) || length(document) != 1 || is.na(document)) {
    stop(
      "document must be the policy's exact text as a single string, ",
      "not a list or an object, because its hash is of the exact text",
      call. = FALSE
    )
  }
  text <- enc2utf8(as.vector(document))
  if (!validUTF8(text)) {
    stop("document is not valid UTF-8", call. = FALSE)
  }
  text
}

# Sample inputs, passed through as given. An empty list is sent as {}.
.policy_inputs <- function(inputs) {
  if (!is.list(inputs) || (length(inputs) > 0 &&
      (is.null(names(inputs)) || any(!nzchar(names(inputs)))))) {
    stop("inputs must be a named list", call. = FALSE)
  }
  if (length(inputs) == 0) {
    return(structure(list(), names = character(0)))
  }
  inputs
}

# A key's own policies are under /policies and its account's under
# /account/policies. The routes take the same bodies and give the same
# responses, so one implementation serves both.
.POLICIES_PATH <- "/policies"
.ACCOUNT_POLICIES_PATH <- "/account/policies"

.policy_path <- function(document_hash, suffix = "", base = .POLICIES_PATH) {
  verdifax_validate_hex64(document_hash, "document_hash")
  paste0(base, "/", document_hash, suffix)
}

.upload_policy_at <- function(client, base, document) {
  .send(client, "POST", base, list(document = .policy_document(document)))
}

.test_policy_at <- function(client, base, caller, inputs, document, document_hash,
                            ai_output_declared = FALSE) {
  if (is.null(document) == is.null(document_hash)) {
    stop(caller, " needs exactly one of document and document_hash", call. = FALSE)
  }
  body <- list(inputs = .policy_inputs(inputs))
  if (!is.null(document)) {
    body$document <- .policy_document(document)
  } else {
    verdifax_validate_hex64(document_hash, "document_hash")
    body$document_hash <- as.vector(document_hash)
  }
  if (!is.logical(ai_output_declared) || length(ai_output_declared) != 1L || is.na(ai_output_declared)) {
    stop("ai_output_declared must be TRUE or FALSE", call. = FALSE)
  }
  if (isTRUE(ai_output_declared)) {
    body$ai_output_declared <- TRUE
  }
  .send(client, "POST", paste0(base, "/test"), body)
}

# Reads the chain and its newest change with `list_policies`, then asks for
# the change naming that newest change, signed when the client has a request
# key. With `signature_required`, a client without one is refused before any
# request, because the server refuses an unsigned change on that chain.
.activate_policy_at <- function(client, base, document_hash, list_policies,
                                signature_required = NULL) {
  path <- .policy_path(document_hash, "/activate", base)
  if (!is.null(signature_required) && is.null(.active_signer(client))) {
    stop(signature_required, call. = FALSE)
  }
  state <- list_policies(client)
  previous <- state[["newest_activation_hash"]]
  if (!is.character(previous) || length(previous) != 1 ||
      !grepl("^[0-9a-f]{64}$", previous)) {
    stop("the server did not return newest_activation_hash, so no change was asked for",
      call. = FALSE)
  }
  body <- list(previous_activation_hash = previous)
  signer <- .active_signer(client)
  if (!is.null(signer)) {
    chain_id <- state[["chain_id"]]
    if (!is.character(chain_id) || length(chain_id) != 1 || !nzchar(chain_id)) {
      stop("the server did not return chain_id, so the change cannot be signed", call. = FALSE)
    }
    body$signature <- .policy_activation(signer, chain_id, document_hash, previous)
  }
  .send(client, "POST", path, body)[["activation"]]
}


# ── Policy routes ───────────────────────────────────────────────────────────

#' Upload a policy document.
#'
#' Calls `POST /policies`. The server stores the exact text and hashes its
#' exact bytes as `document_hash`, so the text is sent as given. Nothing
#' changes until the document is activated with
#' `verdifax_activate_policy()`. Verdifax did not write, review or approve
#' your policy.
#'
#' To send a file's exact bytes, read it whole, for example with
#' `readChar(path, file.size(path), useBytes = TRUE)`: `readLines()` drops
#' the final newline and so changes the hash.
#'
#' @param client A client handle from `verdifax_client()`.
#' @param document The policy's exact text, a single string. A list or any
#'   other object is refused before sending, because serializing it would
#'   change the hash.
#'
#' @return Parsed API response list with `policy_id`, `policy_version`,
#'   `policy_hash`, `document_hash` and `created_at`.
#'
#' @export
verdifax_upload_policy <- function(client, document) {
  .upload_policy_at(client, .POLICIES_PATH, document)
}

#' List this key's policy documents.
#'
#' Calls `GET /policies`.
#'
#' @inheritParams verdifax_upload_policy
#'
#' @return Parsed API response list with `ok`, `chain_id` (for example
#'   `"api-key-7"`), `newest_activation_hash` (64 zeros when nothing has
#'   been activated), `active_document_hash` (empty under the built-in
#'   policy) and `policies`, each as `verdifax_upload_policy()` returns it.
#'
#' @export
verdifax_list_policies <- function(client) {
  .perform(.get(client, .POLICIES_PATH))
}

#' Read one of this key's policy documents.
#'
#' Calls `GET /policies/{document_hash}`.
#'
#' @inheritParams verdifax_upload_policy
#' @param document_hash 64-char lowercase hex hash of the document's exact
#'   text. Anything else is refused before sending.
#'
#' @return Parsed API response list as from `verdifax_upload_policy()`,
#'   with `document`, the exact text.
#'
#' @export
verdifax_get_policy <- function(client, document_hash) {
  .perform(.get(client, .policy_path(document_hash)))
}

#' Show which rule of a policy would fire on sample inputs.
#'
#' Calls `POST /policies/test`. It seals nothing. Give exactly one of
#' `document` and `document_hash`; anything else is refused before sending.
#'
#' @inheritParams verdifax_upload_policy
#' @param inputs A named list of sample inputs, passed through as given,
#'   for example `list(subject_id = "u-1", subject_type = "user",
#'   verb = "approve", object_type = "transaction", classification =
#'   "INTERNAL")`.
#' @param document Optional policy text to test, a single string, as for
#'   `verdifax_upload_policy()`.
#' @param document_hash Optional 64-char lowercase hex hash of a document
#'   already uploaded under this key.
#' @param ai_output_declared `TRUE` when the request being tried declares an
#'   AI output, as `ai_output_text` does on a run: a policy that requires an
#'   AI review refuses a step without one. Sent only when `TRUE`.
#'
#' @return Parsed API response list with `ok`, `sealed` (always `FALSE`),
#'   `outcome`, `fired_rule_id` and `reason_code`.
#'
#' @export
verdifax_test_policy <- function(client, inputs, document = NULL, document_hash = NULL,
                                 ai_output_declared = FALSE) {
  .test_policy_at(client, .POLICIES_PATH, "verdifax_test_policy", inputs, document, document_hash,
                  ai_output_declared)
}

#' The chain of this key's policy changes, oldest first.
#'
#' Calls `GET /policies/history`. Save the text to a file and check it with
#' `verdifax-verify --policy-history FILE`. It is not parsed, so what you
#' save is what the server sent.
#'
#' @inheritParams verdifax_upload_policy
#'
#' @return The exact JSON text the server sent, a list of change records,
#'   as a single string. Read it with `jsonlite::fromJSON()`.
#'
#' @export
verdifax_get_policy_history <- function(client) {
  .get_body_text(client, paste0(.POLICIES_PATH, "/history"))
}

#' Make a stored policy document the policy in force.
#'
#' Reads `GET /policies` for `chain_id` and `newest_activation_hash`, then
#' calls `POST /policies/{document_hash}/activate` naming that newest change.
#' With a `signing_key`, the client's request key signs the change over the
#' chain, the document and the previous change; without one, no signature
#' is sent. Rolling back is activating an earlier document: it is one more
#' change in the chain, so the change it undoes stays on the record.
#'
#' An HTTP 409 means the chain moved because another change came first, or
#' the document is not yet effective; the call stops with the server's
#' message and is not retried.
#'
#' @inheritParams verdifax_get_policy
#'
#' @return The `activation` of the response: the change record.
#'
#' @export
verdifax_activate_policy <- function(client, document_hash) {
  .activate_policy_at(client, .POLICIES_PATH, document_hash, verdifax_list_policies)
}

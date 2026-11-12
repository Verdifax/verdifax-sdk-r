# ----------------------------------------------------------------------------
# verdifax, R SDK for the Verdifax cryptographic attestation pipeline
# ----------------------------------------------------------------------------
#
# This file holds the client, environment capture, attestation, the
# determinism check and request signing. R/runs.R holds run retrieval,
# evidence export and batch runs. R/jobs.R holds job blocks and the job
# helper. R/policies.R holds the policy routes and the policy_context
# checks. R/accounts.R holds the account routes, used with an account's
# owner key, and the admin account routes. R/routes.R holds every other
# route and the provider and admin helpers. R/signals.R holds the signal
# feed, feed keys, webhooks and failure receipts. R/section0.R holds the
# canonical hash formulas. README.md lists every exported function.
#
# All failures from auto-detection are silently swallowed and the
# corresponding field is left NULL. The orchestrator records NULL as
# "not declared" rather than fabricating a claim.
#
# Dependencies (declared in DESCRIPTION):
#   httr2 (>= 1.0.0)
#   jsonlite (>= 1.8.0)
#   openssl, for SHA-256, here and in R/section0.R, and HMAC-SHA256 in
#   R/signals.R
#   sodium (Suggests, needed only for request signing)

# ── Module-level constants ──────────────────────────────────────────────────

.DEFAULT_BASE_URL <- "https://api.verdifax.com"
# A sealed run can take over 30 seconds when the public log is slow; the
# Python, Node and Go SDKs wait 90 seconds, and so does this one.
.DEFAULT_TIMEOUT_SEC <- 90
.REQUEST_KEY_PATH <- "/keys/request-key"
.REQUEST_SIGNATURE_FORM <- "verdifax.request.v1"
.REQUEST_SIGNATURE_V2_FORM <- "verdifax.request.v2"
.REQUEST_SIGNATURE_VERSION <- "2"
.REQUEST_KEY_PROOF_FORM <- "verdifax.request-key.v1"
.REQUEST_KEY_CHANGE_FORM <- "verdifax.request-key-change.v1"
.POLICY_ACTIVATION_FORM <- "verdifax.policy-activation.v1"
.JOB_FORM <- "verdifax.job.v1"
# Every top-level field a run request may hold. The server ignores a field it
# does not know, so a misspelt one would be dropped with no error: a batch
# row with any other name is refused here instead. A test holds this list to
# execute_fields in the shared sdk-parity.json.
.EXECUTE_FIELDS <- c(
  "payload", "payload_text", "program_id", "route_id", "registry_record_hash",
  "ai_output_text", "attested_context", "reproducibility_context",
  "request_substance", "authorization_chain", "regulatory_scaffolding",
  "causal_graph", "request_signature", "signed_request", "job",
  "policy_context", "expected_policy_hash"
)
# Every field of attested_context, for the same reason.
.ATTESTED_CONTEXT_FIELDS <- c(
  "attested", "actor_id", "actor_role", "authorization_policy", "actor_signature",
  "model_provider", "model_name", "model_version", "model_temperature",
  "prompt_hash", "decision_kind", "decision_result", "decision_note"
)
.SIGNING_KEY_BYTES <- 32L
.DEFAULT_MAX_RETRIES <- 3L
.DEFAULT_RETRY_BASE_DELAY_SEC <- 0.2
.RETRYABLE_METHODS <- c("GET", "HEAD", "OPTIONS")
.RETRYABLE_STATUSES <- c(429L, 502L, 503L, 504L)


# ── Client ──────────────────────────────────────────────────────────────────

#' Construct a Verdifax client handle.
#'
#' @param base_url Base URL of the Verdifax API. Falls back to the
#'   environment variable `VERDIFAX_BASE_URL`, then `VERDIFAX_API_URL`,
#'   then to `https://api.verdifax.com`. Trailing slashes are stripped.
#' @param api_key Optional API key sent as the `X-Verdifax-Key`
#'   header. Falls back to the environment variable
#'   `VERDIFAX_API_KEY`.
#' @param timeout Request timeout in seconds. Defaults to 90.
#' @param signing_key Optional raw vector holding the 32 bytes of an
#'   Ed25519 private key, from `verdifax_generate_request_key()`. When
#'   set, `verdifax_attest()`, `verdifax_execute()`,
#'   `verdifax_execute_batch()`, `verdifax_verify_determinism()` and the
#'   provider helpers sign their requests, and `verdifax_activate_policy()`
#'   and `verdifax_activate_account_policy()` sign the change they ask
#'   for. Needs the `sodium` package.
#'   The key is never sent to the server, and the returned list holds it
#'   only inside a closure, so printing the client does not show it.
#' @param user_agent Optional `User-Agent` value.
#' @param max_retries Retries for GET, HEAD and OPTIONS after a network
#'   failure or an HTTP 429, 502, 503 or 504. Defaults to 3; 0 turns them
#'   off. POST is never retried.
#' @param retry_base_delay First retry delay in seconds. It doubles each
#'   retry, with full jitter. Defaults to 0.2.
#'
#' @return A list with named elements (`base_url`, `api_key`,
#'   `timeout`, and `signer` when `signing_key` is set) suitable to
#'   pass to `verdifax_attest()` or `verdifax_verify_determinism()`.
#'
#' @export
verdifax_client <- function(base_url = NULL,
                            api_key = NULL,
                            timeout = .DEFAULT_TIMEOUT_SEC,
                            signing_key = NULL,
                            user_agent = NULL,
                            max_retries = .DEFAULT_MAX_RETRIES,
                            retry_base_delay = .DEFAULT_RETRY_BASE_DELAY_SEC) {
  resolved_url <- base_url %||% .env_base_url()
  if (is.null(resolved_url) || identical(resolved_url, "")) {
    resolved_url <- .DEFAULT_BASE_URL
  }
  resolved_url <- sub("/+$", "", resolved_url)

  resolved_key <- api_key %||% Sys.getenv("VERDIFAX_API_KEY", unset = NA)
  if (is.na(resolved_key) || identical(resolved_key, "")) {
    resolved_key <- NULL
  }

  client <- list(
    base_url = resolved_url,
    api_key = resolved_key,
    timeout = as.numeric(timeout),
    user_agent = user_agent,
    max_retries = as.numeric(max_retries),
    retry_base_delay = as.numeric(retry_base_delay)
  )
  if (!is.null(signing_key)) {
    client$signer <- .request_signer(signing_key)
  }
  client
}


# VERDIFAX_BASE_URL first, then VERDIFAX_API_URL.
.env_base_url <- function() {
  for (name in c("VERDIFAX_BASE_URL", "VERDIFAX_API_URL")) {
    value <- Sys.getenv(name, unset = "")
    if (nzchar(value)) {
      return(value)
    }
  }
  NULL
}


# ── Environment capture ─────────────────────────────────────────────────────

#' Auto-detect the current R research environment.
#'
#' @param declared_seeds Named list of PRNG library to seed value.
#'   Example: `list(rng = 42, torch = 1337)`. The caller is
#'   responsible for actually applying these seeds in their code;
#'   this function records the declarations verbatim. Sorted by name
#'   in the returned list so the canonical JSON is deterministic.
#' @param include_dependencies When `TRUE` (default), enumerate every
#'   installed package via `installed.packages()` and emit
#'   `name==version` strings. Set to `FALSE` for test or sandbox
#'   scenarios where the package list is noisy.
#' @param include_git When `TRUE` (default), attempt to read the
#'   current git commit SHA via `git rev-parse HEAD`. Silently falls
#'   back to `NULL` if not in a git repo or git is unavailable.
#' @param include_container When `TRUE` (default), attempt to read
#'   the Docker container ID from `/proc/self/cgroup` on Linux.
#'   Silently falls back to `NULL` outside containers or on
#'   non-Linux platforms.
#'
#' @return A named list shaped to match the Verdifax
#'   `ReproducibilityContext` JSON contract. Suitable to pass into
#'   `verdifax_attest()` or `verdifax_verify_determinism()` as
#'   `reproducibility_context`.
#'
#' @export
verdifax_capture_environment <- function(declared_seeds = list(),
                                         include_dependencies = TRUE,
                                         include_git = TRUE,
                                         include_container = TRUE) {
  runtime_name <- "R"
  runtime_version <- paste(R.version$major, R.version$minor, sep = ".")

  # GOOS/GOARCH-style platform descriptor.
  sysinfo <- Sys.info()
  os <- tolower(sysinfo[["sysname"]])  # 'darwin', 'linux', 'windows'
  if (identical(os, "windows")) os <- "windows"
  arch <- tolower(sysinfo[["machine"]])  # 'x86_64', 'arm64', 'aarch64'
  arch <- switch(arch,
    "x86_64" = "amd64",
    "aarch64" = "arm64",
    arch
  )
  platform_descriptor <- paste0(os, "/", arch)

  pinned <- NULL
  if (isTRUE(include_dependencies)) {
    pinned <- .enumerate_dependencies()
  }

  git_sha <- if (isTRUE(include_git)) .detect_git_sha() else NULL
  container_hash <- if (isTRUE(include_container)) .detect_container_hash() else NULL

  seeds_list <- NULL
  if (length(declared_seeds) > 0) {
    keys <- sort(names(declared_seeds))
    # USE.NAMES = FALSE: vapply over a character vector names its result
    # by default. A named vector serializes as a JSON object (despite
    # the I() wrapper applied later), which the orchestrator's Go
    # []string field rejects; random_seeds must be an unnamed array.
    seeds_list <- vapply(
      keys,
      function(k) paste0(k, "=", as.character(declared_seeds[[k]])),
      character(1),
      USE.NAMES = FALSE
    )
  }

  ctx <- list(
    container_image_hash = container_hash,
    runtime_name = runtime_name,
    runtime_version = runtime_version,
    pinned_dependencies = pinned,
    git_commit_sha = git_sha,
    random_seeds = seeds_list,
    platform = platform_descriptor
  )

  # declared flag: TRUE when at least one descriptive field is non-empty
  ctx$declared <- any(
    !is.null(ctx$container_image_hash),
    !is.null(ctx$runtime_name),
    !is.null(ctx$runtime_version),
    length(ctx$pinned_dependencies) > 0,
    !is.null(ctx$git_commit_sha),
    length(ctx$random_seeds) > 0,
    !is.null(ctx$platform)
  )

  # Drop NULL entries, jsonlite will skip them, but explicit removal
  # makes the JSON shape match what the Python wrapper produces.
  ctx[!vapply(ctx, is.null, logical(1))]
}


.enumerate_dependencies <- function() {
  tryCatch({
    pkgs <- utils::installed.packages()
    if (is.null(pkgs) || nrow(pkgs) == 0) {
      return(NULL)
    }
    deps <- paste0(pkgs[, "Package"], "==", pkgs[, "Version"])
    # Sort case-insensitive for canonical JSON
    deps[order(tolower(deps))]
  }, error = function(e) {
    NULL
  })
}


.detect_git_sha <- function() {
  tryCatch({
    # Suppress stderr; we want a silent fail on non-git directories.
    result <- suppressWarnings(
      system2(
        "git",
        args = c("rev-parse", "HEAD"),
        stdout = TRUE,
        stderr = FALSE,
        timeout = 2
      )
    )
    sha <- trimws(result[1])
    # Sanity: 40 hex chars (sha1) or 64 (sha256-mode).
    if (nchar(sha) %in% c(40, 64) &&
        grepl("^[0-9a-f]+$", tolower(sha))) {
      tolower(sha)
    } else {
      NULL
    }
  }, error = function(e) NULL)
}


.detect_container_hash <- function() {
  cgroup_path <- "/proc/self/cgroup"
  if (!file.exists(cgroup_path)) {
    return(NULL)
  }
  tryCatch({
    lines <- readLines(cgroup_path, warn = FALSE)
    for (line in lines) {
      segments <- strsplit(line, "/", fixed = TRUE)[[1]]
      for (seg in trimws(segments)) {
        if (nchar(seg) == 64 && grepl("^[0-9a-f]+$", seg)) {
          return(seg)
        }
      }
    }
    NULL
  }, error = function(e) NULL)
}


# ── HTTP helpers ────────────────────────────────────────────────────────────

.build_request <- function(client, path, body, method = "POST", query = NULL) {
  req <- httr2::request(client$base_url)
  req <- httr2::req_url_path(req, path)
  if (length(query) > 0) {
    req <- do.call(httr2::req_url_query, c(list(req), query))
  }
  req <- httr2::req_method(req, method)
  req <- httr2::req_headers(
    req,
    "Content-Type" = "application/json",
    "Accept" = "application/json",
    "User-Agent" = client$user_agent %||% paste0(
      "verdifax-r/", utils::packageVersion("verdifax")
    )
  )
  if (!is.null(client$api_key)) {
    req <- httr2::req_headers(req, "X-Verdifax-Key" = client$api_key)
  }
  if (!is.null(body)) {
    req <- httr2::req_body_json(req, body, auto_unbox = TRUE)
  }
  req <- httr2::req_timeout(req, client$timeout)
  .with_retries(client, req, method)
}

# GET, HEAD and OPTIONS retry after a network failure or a transient
# status, with exponential backoff and full jitter, the same attempts and
# backoff as the Node and Go SDKs. POST and DELETE are never retried:
# replaying one could run it twice, and a retried signed request would be
# refused as a replay.
.with_retries <- function(client, req, method) {
  retries <- client$max_retries %||% .DEFAULT_MAX_RETRIES
  if (!method %in% .RETRYABLE_METHODS || retries <= 0) {
    return(req)
  }
  base_delay <- client$retry_base_delay %||% .DEFAULT_RETRY_BASE_DELAY_SEC
  httr2::req_retry(
    req,
    max_tries = retries + 1,
    retry_on_failure = TRUE,
    is_transient = function(resp) httr2::resp_status(resp) %in% .RETRYABLE_STATUSES,
    backoff = function(attempt) stats::runif(1, 0, base_delay * 2^(attempt - 1)),
    after = function(resp) NA
  )
}

.perform <- function(req) {
  resp <- httr2::req_perform(req)
  body <- httr2::resp_body_string(resp)
  parsed <- jsonlite::fromJSON(body, simplifyVector = FALSE)
  parsed
}

# The server's own message, added to the httr2 error for a non-2xx
# response. NULL when the body is not the JSON error envelope.
.error_detail <- function(resp) {
  tryCatch({
    detail <- jsonlite::fromJSON(httr2::resp_body_string(resp), simplifyVector = FALSE)[["error"]]
    if (is.character(detail) && length(detail) == 1) detail else NULL
  }, error = function(e) NULL)
}


# A string field of a refused or halted run's error body, or NULL.
.error_field <- function(error, name) {
  tryCatch({
    value <- jsonlite::fromJSON(httr2::resp_body_string(error$resp), simplifyVector = FALSE)[[name]]
    if (is.character(value) && length(value) == 1 && nzchar(value)) value else NULL
  }, error = function(e) NULL)
}

# The record_hash of a refused or halted run, from the error body.
.error_record_hash <- function(error) .error_field(error, "record_hash")

# Posts one execute body. A refused or halted run answers with an error
# status and still leaves a record, so the same error goes on, holding the
# server's message, that record's hash, the text that was signed and, for a
# run the AI review halted, the trace it checked (aivp_trace_text). A run
# that completes carries the trace as `aivp_trace_text` and the sealed
# review as `manifest$AivpReview`.
.post_execute <- function(client, path, body) {
  wire <- .attach_signature(client, body)
  signed_request <- wire[["signed_request"]]
  req <- httr2::req_error(.build_request(client, path, wire), body = .error_detail)
  result <- tryCatch(
    .perform(req),
    httr2_http = function(error) {
      error$record_hash <- .error_record_hash(error)
      error$signed_request <- signed_request
      # The text the AI review checked, on a run its review halted:
      # returned once, and the halt receipt seals its hash.
      error$aivp_trace_text <- .error_field(error, "aivp_trace_text")
      stop(error)
    }
  )
  result$signed_request <- signed_request
  result
}


# ── Attestation ─────────────────────────────────────────────────────────────

#' Attest a payload through the Verdifax pipeline.
#'
#' @param client A client handle from `verdifax_client()`.
#' @param payload The payload to attest. Character strings are sent
#'   as UTF-8 text; raw vectors get base64-encoded.
#' @param program_id 64-char lowercase hex program ID.
#' @param route_id Non-empty deterministic route identifier.
#' @param registry_record_hash 64-char lowercase hex §0 record hash.
#' @param reproducibility_context Optional list shaped like the
#'   output of `verdifax_capture_environment()`. Bound into the
#'   audit bundle's Category-6 section.
#' @param ai_output_text Optional AI output text for AIVP
#'   governance.
#' @param attested_context Optional named list of caller-attested actor,
#'   model and decision fields, recorded in the audit bundle: `actor_id`,
#'   `actor_role`, `authorization_policy`, `actor_signature`,
#'   `model_provider`, `model_name`, `model_version`, `model_temperature`,
#'   `prompt_hash`, `decision_kind`, `decision_result` and `decision_note`.
#'   Any other name is refused before sending. `attested` is set from
#'   whether any other field has a value.
#' @param request_substance Optional named list of prompt, output, cost,
#'   latency and origin metadata, recorded as supplied. Leave out
#'   `origin$source_ip_hash` and `origin$user_agent_hash`: the server
#'   computes those, and they are refused here.
#' @param authorization_chain Optional named list holding the approval
#'   chain, recorded as supplied and not verified by Verdifax.
#' @param regulatory_scaffolding Optional named list of regulatory
#'   metadata, recorded as supplied and not an assessment by Verdifax.
#' @param causal_graph Optional named list recording what led to this
#'   run, recorded as supplied.
#' @param job Optional named list placing this run in a job: `job_id`,
#'   `step_id`, and optionally `previous_record_hashes`,
#'   `external_previous` and `final`. Bad names are refused before
#'   sending. The hash lists are sorted and repeats removed for you.
#'   `verdifax_job_step()` builds this for you.
#' @param policy_context Optional named list of what this request declares
#'   for your active policy's rules to read, with only these fields:
#'   `actor_type` (`"agent"`, `"user"`, `"service"` or `"system"`),
#'   `mfa_satisfied` (`TRUE` or `FALSE`), `session_age_seconds` (a whole
#'   number, not negative), `object_type` (`"text"`, `"transaction"`,
#'   `"code"`, `"data"`, `"model"` or `"file"`), `object_id` (text of at
#'   most 256 bytes) and `classification` (`"PUBLIC"`, `"INTERNAL"`,
#'   `"CONFIDENTIAL"`, `"RESTRICTED"`, `"TOP_SECRET"` or `"TS_SCI"`), and
#'   `data_quality`, your declaration about the data the decision used: a
#'   named list of `source` (at most 200 bytes), `as_of` (a time such as
#'   `"2026-11-11T09:00:00Z"`) and `checks`, an unnamed list of up to 50
#'   checks, each `list(name = , result = )` with a distinct name and a
#'   result of `"pass"`, `"fail"` or `"warn"`. Verdifax judges none of it. An
#'   unknown field or a value outside these is refused before sending, so a
#'   misspelt field is never dropped. `actor_type`, `mfa_satisfied` and
#'   `session_age_seconds` describe the attested actor, so a set
#'   `actor_type`, `mfa_satisfied = TRUE` or a non-zero
#'   `session_age_seconds` needs an `attested_context` with at least one
#'   field set, such as `actor_id`. The rules judge what you declare here;
#'   they cannot show it is true.
#' @param expected_policy_hash Optional 64-char lowercase hex `policy_hash`
#'   of the policy you expect to be active. When another policy is active,
#'   the server refuses the run with HTTP 409.
#'
#' @return Parsed API response list with `ok`, `run_id`, `record_hash`,
#'   `manifest`, etc. A signed call also has `signed_request`, the exact
#'   JSON text that was signed, to keep for
#'   `verdifax-verify --request FILE`. A refused or halted run stops with
#'   the httr2 error, and that condition holds `record_hash` and, for a
#'   signed call, `signed_request`.
#'
#' @export
verdifax_attest <- function(client,
                            payload,
                            program_id,
                            route_id,
                            registry_record_hash,
                            reproducibility_context = NULL,
                            ai_output_text = NULL,
                            attested_context = NULL,
                            request_substance = NULL,
                            authorization_chain = NULL,
                            regulatory_scaffolding = NULL,
                            causal_graph = NULL,
                            job = NULL,
                            policy_context = NULL,
                            expected_policy_hash = NULL) {
  body <- .build_execute_body(
    payload = payload,
    program_id = program_id,
    route_id = route_id,
    registry_record_hash = registry_record_hash,
    reproducibility_context = reproducibility_context,
    ai_output_text = ai_output_text,
    attested_context = attested_context,
    request_substance = request_substance,
    authorization_chain = authorization_chain,
    regulatory_scaffolding = regulatory_scaffolding,
    causal_graph = causal_graph,
    job = job,
    policy_context = policy_context,
    expected_policy_hash = expected_policy_hash
  )
  .post_execute(client, "/execute", body)
}


# ── Determinism verification ────────────────────────────────────────────────

#' Verify the pipeline produces byte-identical evidence on replay.
#'
#' Runs the same payload through the Verdifax pipeline twice in
#' immediate succession (server-side pinned clock) and returns the
#' comparison summary.
#'
#' The top-level `deterministic` flag is grounded on manifest hash
#' equality, the canonical seal of the pipeline output. Bundle hash
#' differences are surfaced in `diff$differing_fields` as
#' informational metadata (server-observed timing variation). A request
#' the policy refuses, or a later check halts, is compared the same way:
#' each refused run's row carries its sealed `receipt`, and two identical
#' refusals are deterministic. When neither run sealed a record,
#' `diff$reason` says why there is no verdict.
#'
#' With a `signing_key`, one signature covers the request, and the
#' server claims its nonce once.
#'
#' @inheritParams verdifax_attest
#'
#' @return Parsed API response list with `deterministic`, `first`,
#'   `second`, and `diff` fields. A signed call also has
#'   `signed_request`, the exact JSON text that was signed.
#'
#' @export
verdifax_verify_determinism <- function(client,
                                        payload,
                                        program_id,
                                        route_id,
                                        registry_record_hash,
                                        reproducibility_context = NULL,
                                        ai_output_text = NULL,
                                        attested_context = NULL,
                                        request_substance = NULL,
                                        authorization_chain = NULL,
                                        regulatory_scaffolding = NULL,
                                        causal_graph = NULL,
                                        policy_context = NULL,
                                        expected_policy_hash = NULL) {
  body <- .build_execute_body(
    payload = payload,
    program_id = program_id,
    route_id = route_id,
    registry_record_hash = registry_record_hash,
    reproducibility_context = reproducibility_context,
    ai_output_text = ai_output_text,
    attested_context = attested_context,
    request_substance = request_substance,
    authorization_chain = authorization_chain,
    regulatory_scaffolding = regulatory_scaffolding,
    causal_graph = causal_graph,
    policy_context = policy_context,
    expected_policy_hash = expected_policy_hash
  )
  .post_execute(client, "/execute/verify-determinism", body)
}


# ── Request signing ─────────────────────────────────────────────────────────

#' Create an Ed25519 key pair for request signing.
#'
#' The key pair is made on this machine and nothing is sent to the
#' server. Pass `private_key` as `signing_key` to `verdifax_client()`,
#' and store it as a secret. Needs the `sodium` package.
#'
#' @return A list with raw vectors `public_key` (32 bytes) and
#'   `private_key` (32 bytes).
#'
#' @export
verdifax_generate_request_key <- function() {
  .require_sodium()
  private_key <- sodium::random(.SIGNING_KEY_BYTES)
  list(
    public_key = sodium::sig_pubkey(sodium::sig_keygen(private_key)),
    private_key = private_key
  )
}

#' Register the client's public key on its API key.
#'
#' Sends the public key with a proof that this client holds the
#' private key. From then on the server refuses a run on this API key
#' without a request signature.
#'
#' @param client A client handle from `verdifax_client()`, constructed
#'   with `signing_key`.
#'
#' @return Parsed API response list with `ok` and `public_key`.
#'
#' @export
verdifax_register_request_key <- function(client) {
  signer <- .active_signer(client)
  if (is.null(signer)) {
    stop(
      "verdifax_register_request_key needs a client with signing_key",
      call. = FALSE
    )
  }
  body <- .request_key_body(signer)
  .perform(.build_request(client, .REQUEST_KEY_PATH, body))
}

#' Replace the registered public key.
#'
#' The server needs the current key to approve the change, so this sends
#' the new public key with its proof, made by the new key, and an approval
#' made by the current key. After success the client signs with the new
#' key, and so does every copy of the client, such as one held by a job.
#' After a failure it keeps the current key.
#'
#' @param client A client handle from `verdifax_client()`, constructed
#'   with the current `signing_key`.
#' @param new_signing_key The 32 raw bytes of the new Ed25519 private key.
#'
#' @return Parsed API response list with `ok` and `public_key`.
#'
#' @export
verdifax_rotate_request_key <- function(client, new_signing_key) {
  signer <- .active_signer(client)
  if (is.null(signer)) {
    stop(
      "verdifax_rotate_request_key needs a client with signing_key",
      call. = FALSE
    )
  }
  replacement <- .request_signer(new_signing_key)
  body <- .request_key_body(replacement)
  body$change <- .key_change(signer, body[["public_key"]])
  result <- .send(client, "POST", .REQUEST_KEY_PATH, body)
  .adopt_signer(signer, replacement)
  result
}

#' Clear the registered public key.
#'
#' The server stops requiring request signatures on this API key. Once a
#' key is registered, the server needs that key to approve clearing it,
#' so call this with a client that holds it. After success the client
#' drops its signing key and sends unsigned requests, because the server
#' refuses a signed run on this API key, and so does every copy of the
#' client, such as one held by a job. After a failure it keeps the key.
#'
#' @param client A client handle from `verdifax_client()`.
#'
#' @return Parsed API response list with `ok`.
#'
#' @export
verdifax_clear_request_key <- function(client) {
  signer <- .active_signer(client)
  body <- if (!is.null(signer)) list(change = .key_change(signer, ""))
  result <- .send(client, "DELETE", .REQUEST_KEY_PATH, body)
  if (!is.null(signer)) {
    .drop_signer(signer)
  }
  result
}

.sodium_available <- function() {
  requireNamespace("sodium", quietly = TRUE)
}

.require_sodium <- function() {
  if (!.sodium_available()) {
    stop(
      "request signing needs the sodium package: install.packages(\"sodium\")",
      call. = FALSE
    )
  }
  invisible(TRUE)
}

# The key stays inside these closures, so printing the client shows
# no key bytes. sodium::sig_sign() takes the 64-byte form that
# sig_keygen() builds from the 32 raw bytes. The signer is an environment
# because a client is a list, copied on assignment, and rotating a key has
# to reach the caller's client and any job holding a copy of it.
.request_signer <- function(signing_key) {
  if (!is.raw(signing_key) || length(signing_key) != .SIGNING_KEY_BYTES) {
    stop(
      "signing_key must be the 32 raw bytes of an Ed25519 private key",
      call. = FALSE
    )
  }
  .require_sodium()
  expanded <- sodium::sig_keygen(signing_key)
  signer <- new.env(parent = emptyenv())
  signer$public_key <- sodium::sig_pubkey(expanded)
  signer$sign <- function(message) sodium::sig_sign(message, expanded)
  signer
}

.adopt_signer <- function(signer, replacement) {
  signer$public_key <- replacement$public_key
  signer$sign <- replacement$sign
  invisible(signer)
}

# Letting go of the closure lets go of the key.
.drop_signer <- function(signer) {
  signer$public_key <- NULL
  signer$sign <- NULL
  invisible(signer)
}

# The client's signer, or NULL when it has none or has dropped it.
.active_signer <- function(client) {
  signer <- client$signer
  if (is.null(signer) || is.null(signer$sign)) NULL else signer
}

# The string as the server will decode it: put through the JSON
# encoding req_body_json() uses, so the locale and the string's
# declared encoding cannot make the signed bytes differ from the sent
# ones.
.wire_string <- function(value) {
  json <- jsonlite::toJSON(list(value = value), auto_unbox = TRUE)
  decoded <- jsonlite::fromJSON(json, simplifyVector = FALSE)[["value"]]
  if (!is.character(decoded) || length(decoded) != 1) {
    stop("request values must be single strings to be signed", call. = FALSE)
  }
  decoded
}

# jsonlite::base64_enc() wraps its output at 72 characters.
.base64 <- function(bytes) {
  gsub("\n", "", jsonlite::base64_enc(bytes), fixed = TRUE)
}

.utf8_bytes <- function(value) {
  charToRaw(enc2utf8(value))
}

# Fields joined with single zero bytes. R strings cannot hold one, so
# this works on raw vectors.
.join_with_zero <- function(fields) {
  Reduce(function(a, b) c(a, as.raw(0), b), lapply(fields, .utf8_bytes))
}

# The server hashes payload_text when it is non-empty, otherwise the
# payload string exactly as sent. It does not base64-decode it. The
# lookups use [[ ]] because body$payload would partially match
# payload_text.
.payload_hash <- function(body) {
  payload <- body[["payload_text"]]
  if (is.null(payload) || identical(payload, "")) {
    payload <- body[["payload"]]
  }
  if (is.null(payload)) {
    payload <- ""
  }
  .sha256_hex(.wire_string(payload))
}

.signing_time <- function() {
  format(Sys.time(), "%Y-%m-%dT%H:%M:%SZ", tz = "UTC")
}

.signing_nonce <- function() {
  sodium::bin2hex(sodium::random(16))
}

# Version 1, kept for verdifax_sign_request(). A client sends version 2.
.request_signature <- function(signer, body, signed_at = NULL, nonce = NULL) {
  signed_at <- signed_at %||% .signing_time()
  nonce <- nonce %||% .signing_nonce()
  preimage <- .join_with_zero(list(
    .REQUEST_SIGNATURE_FORM,
    .payload_hash(body),
    .wire_string(body[["program_id"]]),
    .wire_string(body[["route_id"]]),
    .wire_string(body[["registry_record_hash"]]),
    signed_at,
    nonce
  ))
  list(
    signature = .base64(signer$sign(preimage)),
    signed_at = signed_at,
    nonce = nonce
  )
}

# The request as one JSON text, with the options req_body_json() uses, so
# signing does not change how any value is written. The text is UTF-8
# whatever the locale, and this is the only time it is serialized.
.request_text <- function(body) {
  text <- as.character(jsonlite::toJSON(body, auto_unbox = TRUE, digits = 22, null = "null"))
  Encoding(text) <- "UTF-8"
  text
}

# A field as the signed text holds it. A missing field is the empty string
# and the server refuses that row on its fields, not on its signature.
.request_field <- function(request, name) {
  value <- request[[name]]
  if (is.null(value)) "" else .wire_string(value)
}

.ai_output_hash <- function(request) {
  text <- .request_field(request, "ai_output_text")
  if (identical(text, "")) "" else .sha256_hex(text)
}

# With no job, job_id, step_id and both lists are empty and final is false.
.job_preimage_fields <- function(job) {
  list(
    .JOB_FORM,
    job[["job_id"]] %||% "",
    job[["step_id"]] %||% "",
    paste(unlist(job[["previous_record_hashes"]]), collapse = ","),
    paste(unlist(job[["external_previous"]]), collapse = ","),
    if (isTRUE(job[["final"]])) "true" else "false"
  )
}

.request_preimage_v2 <- function(body_hash, payload_hash, program_id, route_id,
                                 registry_record_hash, ai_output_hash, job,
                                 signed_at, nonce) {
  .join_with_zero(c(
    list(
      .REQUEST_SIGNATURE_V2_FORM, body_hash, payload_hash, program_id, route_id,
      registry_record_hash, ai_output_hash
    ),
    .job_preimage_fields(job),
    list(signed_at, nonce)
  ))
}

# Every value comes from the text itself, so what is signed is what the
# server will read, in any locale and with nothing rebuilt.
.signed_text_preimage <- function(text, signed_at, nonce) {
  request <- jsonlite::fromJSON(text, simplifyVector = FALSE)
  .request_preimage_v2(
    body_hash = .sha256_hex(text),
    payload_hash = .payload_hash(request),
    program_id = .request_field(request, "program_id"),
    route_id = .request_field(request, "route_id"),
    registry_record_hash = .request_field(request, "registry_record_hash"),
    ai_output_hash = .ai_output_hash(request),
    job = request[["job"]],
    signed_at = signed_at,
    nonce = nonce
  )
}

.signed_body <- function(signer, text, signed_at = NULL, nonce = NULL) {
  signed_at <- signed_at %||% .signing_time()
  nonce <- nonce %||% .signing_nonce()
  list(
    signed_request = text,
    request_signature = list(
      version = .REQUEST_SIGNATURE_VERSION,
      signature = .base64(signer$sign(.signed_text_preimage(text, signed_at, nonce))),
      signed_at = signed_at,
      nonce = nonce
    )
  )
}

# With no signer the body is returned unchanged.
.attach_signature <- function(client, body) {
  signer <- .active_signer(client)
  if (is.null(signer)) {
    return(body)
  }
  .signed_body(signer, .request_text(body))
}

.request_key_body <- function(signer) {
  public_key <- .base64(signer$public_key)
  proof <- signer$sign(.join_with_zero(list(.REQUEST_KEY_PROOF_FORM, public_key)))
  list(public_key = public_key, proof = .base64(proof))
}

# The current key's approval of a change. new_public_key is the new key as
# base64, or the empty string when clearing.
.key_change <- function(signer, new_public_key, signed_at = NULL, nonce = NULL) {
  signed_at <- signed_at %||% .signing_time()
  nonce <- nonce %||% .signing_nonce()
  preimage <- .join_with_zero(list(.REQUEST_KEY_CHANGE_FORM, new_public_key, signed_at, nonce))
  list(signature = .base64(signer$sign(preimage)), signed_at = signed_at, nonce = nonce)
}

# The request key's approval of a policy change: the `signature` object of
# the activate body. chain_id ties it to one API key's chain of changes.
.policy_activation <- function(signer, chain_id, document_hash, previous_activation_hash,
                               signed_at = NULL, nonce = NULL) {
  signed_at <- signed_at %||% .signing_time()
  nonce <- nonce %||% .signing_nonce()
  preimage <- verdifax_policy_activation_preimage(
    chain_id, document_hash, previous_activation_hash, signed_at, nonce
  )
  list(signature = .base64(signer$sign(preimage)), signed_at = signed_at, nonce = nonce)
}


# ── Internal: request body builder ──────────────────────────────────────────

.build_execute_body <- function(payload,
                                program_id,
                                route_id,
                                registry_record_hash,
                                reproducibility_context = NULL,
                                ai_output_text = NULL,
                                attested_context = NULL,
                                request_substance = NULL,
                                authorization_chain = NULL,
                                regulatory_scaffolding = NULL,
                                causal_graph = NULL,
                                job = NULL,
                                policy_context = NULL,
                                expected_policy_hash = NULL) {
  verdifax_validate_hex64(program_id, "program_id")
  verdifax_validate_hex64(registry_record_hash, "registry_record_hash")
  verdifax_validate_route_id(route_id)
  if (is.null(payload)) {
    stop("payload must be character or raw")
  }
  .refuse_origin_hashes(request_substance)
  .execute_fields(
    payload = payload,
    program_id = program_id,
    route_id = route_id,
    registry_record_hash = registry_record_hash,
    reproducibility_context = reproducibility_context,
    ai_output_text = ai_output_text,
    attested_context = attested_context,
    request_substance = request_substance,
    authorization_chain = authorization_chain,
    regulatory_scaffolding = regulatory_scaffolding,
    causal_graph = causal_graph,
    job = job,
    policy_context = policy_context,
    expected_policy_hash = expected_policy_hash
  )
}

# The server computes these two fields and refuses a request that sets
# them, on POST /execute and in each row of a batch.
.refuse_origin_hashes <- function(substance) {
  origin <- substance[["origin"]]
  for (name in c("source_ip_hash", "user_agent_hash")) {
    value <- origin[[name]]
    if (!is.null(value) && !identical(value, "")) {
      stop(
        "request_substance$origin$source_ip_hash and user_agent_hash are ",
        "computed by the server and cannot be supplied",
        call. = FALSE
      )
    }
  }
  invisible(TRUE)
}

# A field counts as provided unless it is NULL, empty text or FALSE.
.is_provided <- function(value) {
  !is.null(value) && !identical(value, "") && !identical(value, FALSE)
}

# The attested flag follows the fields, in all four SDKs, so a policy
# that reads the flag sees what the caller declared. An unknown field is
# refused, because the server would drop it with no error.
.attested_block <- function(context) {
  if (!is.list(context) || (length(context) > 0 && is.null(names(context)))) {
    stop("attested_context must be a named list", call. = FALSE)
  }
  unknown <- setdiff(names(context), .ATTESTED_CONTEXT_FIELDS)
  if (length(unknown) > 0) {
    stop(
      "attested_context has an unknown field: ", paste(unknown, collapse = ", "),
      call. = FALSE
    )
  }
  context <- context[!vapply(context, is.null, logical(1))]
  fields <- context[setdiff(names(context), "attested")]
  context$attested <- any(vapply(fields, .is_provided, logical(1)))
  context
}

# The declared flag follows the fields in the same way. An empty vector
# declares nothing.
.declared_flag <- function(context) {
  fields <- context[setdiff(names(context), "declared")]
  any(vapply(fields, function(value) .is_provided(value) && length(value) > 0, logical(1)))
}

# The fields of one execute body, with no checks on their values, so a
# batch can leave a bad row for the server to report in its result. A job
# block, policy_context and expected_policy_hash are the exceptions: a bad
# one is refused here, so a misspelt field is never dropped.
.execute_fields <- function(payload,
                            program_id,
                            route_id,
                            registry_record_hash,
                            reproducibility_context = NULL,
                            ai_output_text = NULL,
                            attested_context = NULL,
                            request_substance = NULL,
                            authorization_chain = NULL,
                            regulatory_scaffolding = NULL,
                            causal_graph = NULL,
                            job = NULL,
                            policy_context = NULL,
                            expected_policy_hash = NULL) {
  body <- list(
    program_id = program_id,
    route_id = route_id,
    registry_record_hash = registry_record_hash
  )

  if (is.character(payload)) {
    body$payload_text <- payload
  } else if (is.raw(payload)) {
    # Best-effort: try UTF-8 decode first; fall back to base64.
    text <- tryCatch(
      rawToChar(payload),
      error = function(e) NA_character_
    )
    if (!is.na(text) && validUTF8(text)) {
      body$payload_text <- text
    } else {
      body$payload <- jsonlite::base64_enc(payload)
    }
  } else if (!is.null(payload)) {
    stop("payload must be character or raw")
  }

  if (!is.null(ai_output_text) && nzchar(ai_output_text)) {
    body$ai_output_text <- ai_output_text
  }

  if (!is.null(attested_context)) {
    body$attested_context <- .attested_block(attested_context)
  }

  if (!is.null(reproducibility_context)) {
    # Filter NULL entries before sending; orchestrator handles
    # missing fields as "not declared".
    ctx <- reproducibility_context[!vapply(reproducibility_context, is.null, logical(1))]
    ctx$declared <- .declared_flag(ctx)
    # Force array-valued fields to serialize as JSON arrays even at
    # length 1. Without I(), jsonlite's auto_unbox=TRUE would emit a
    # single-element character vector as a JSON scalar string, which
    # the orchestrator's Go struct rejects with
    # `cannot unmarshal string into Go struct field ... of type []string`.
    for (array_field in c("pinned_dependencies", "random_seeds")) {
      if (!is.null(ctx[[array_field]])) {
        ctx[[array_field]] <- I(ctx[[array_field]])
      }
    }
    body$reproducibility_context <- ctx
  }

  # A NULL block stays out of the list, so it stays off the wire.
  body$request_substance <- request_substance
  body$authorization_chain <- authorization_chain
  body$regulatory_scaffolding <- regulatory_scaffolding
  body$causal_graph <- causal_graph

  if (!is.null(job)) {
    body$job <- .job_block(job)
  }

  if (!is.null(policy_context)) {
    body$policy_context <- .policy_context_block(
      policy_context, isTRUE(body$attested_context$attested)
    )
  }

  if (!is.null(expected_policy_hash)) {
    verdifax_validate_hex64(expected_policy_hash, "expected_policy_hash")
    body$expected_policy_hash <- as.vector(expected_policy_hash)
  }

  body
}


# ── Utilities ───────────────────────────────────────────────────────────────

# Null-coalescing operator: returns the right side if the left is NULL.
`%||%` <- function(x, y) if (is.null(x)) y else x

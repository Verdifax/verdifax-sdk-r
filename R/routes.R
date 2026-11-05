# ----------------------------------------------------------------------------
# verdifax, the remaining routes and the provider and admin helpers
# ----------------------------------------------------------------------------

.send <- function(client, method, path, body = NULL) {
  req <- .build_request(client, path, body, method = method)
  .perform(httr2::req_error(req, body = .error_detail))
}

.get_body_text <- function(client, path) {
  httr2::resp_body_string(httr2::req_perform(.get(client, path)))
}

.require_id <- function(value, name) {
  if (!is.numeric(value) || length(value) != 1 || is.na(value) ||
      value <= 0 || value != floor(value)) {
    stop(name, " must be a positive whole number", call. = FALSE)
  }
  format(value, scientific = FALSE, trim = TRUE)
}


# ── Service ─────────────────────────────────────────────────────────────────

.env_number <- function(name) {
  raw <- Sys.getenv(name, unset = "")
  if (!nzchar(raw)) {
    return(NULL)
  }
  if (!grepl("^-?[0-9]+$", raw)) {
    stop(name, "=", raw, " is not an integer", call. = FALSE)
  }
  as.numeric(raw)
}

#' Build a client from the environment.
#'
#' Reads `VERDIFAX_BASE_URL`, then `VERDIFAX_API_URL`, and
#' `VERDIFAX_API_KEY`, `VERDIFAX_TIMEOUT_MS`, `VERDIFAX_USER_AGENT` and
#' `VERDIFAX_MAX_RETRIES`. Stops with an error when the timeout or the
#' retry count is not an integer.
#'
#' @return A client handle.
#'
#' @export
verdifax_from_env <- function() {
  timeout_ms <- .env_number("VERDIFAX_TIMEOUT_MS")
  retries <- .env_number("VERDIFAX_MAX_RETRIES")
  user_agent <- Sys.getenv("VERDIFAX_USER_AGENT", unset = "")
  verdifax_client(
    timeout = if (is.null(timeout_ms)) .DEFAULT_TIMEOUT_SEC else timeout_ms / 1000,
    user_agent = if (nzchar(user_agent)) user_agent else NULL,
    max_retries = if (is.null(retries)) .DEFAULT_MAX_RETRIES else retries
  )
}

#' Liveness check, from `GET /health`.
#'
#' @param client A client handle from `verdifax_client()`.
#'
#' @return Parsed API response list.
#'
#' @export
verdifax_health <- function(client) {
  .perform(.get(client, "/health"))
}

#' Deploy details, from `GET /version`.
#'
#' @inheritParams verdifax_health
#'
#' @return Parsed API response list.
#'
#' @export
verdifax_version <- function(client) {
  .perform(.get(client, "/version"))
}

#' The server's own API description, from `GET /openapi.json`.
#'
#' @inheritParams verdifax_health
#'
#' @return Parsed API response list.
#'
#' @export
verdifax_get_openapi <- function(client) {
  .perform(.get(client, "/openapi.json"))
}

#' Run counts for this API key, from `GET /stats`.
#'
#' @inheritParams verdifax_health
#'
#' @return Parsed API response list.
#'
#' @export
verdifax_get_stats <- function(client) {
  .perform(.get(client, "/stats"))
}

#' Every status the server gives a run.
#'
#' @return A character vector.
#'
#' @export
verdifax_run_statuses <- function() {
  c(
    "ok", "probe", "pepg_deny", "ccv_halt", "macc_halt",
    "aivp_t4_halt", "attestation_gap", "stage_error"
  )
}

#' Run the pipeline and return just the manifest.
#'
#' A lower-level alternative to `verdifax_attest()`.
#'
#' @inheritParams verdifax_attest
#'
#' @return The parsed `manifest` of the response.
#'
#' @export
verdifax_execute <- function(client,
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
                             causal_graph = NULL) {
  verdifax_attest(
    client = client,
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
    causal_graph = causal_graph
  )[["manifest"]]
}

#' Submit a proof bundle for stateless DCAE verification.
#'
#' Calls `POST /dcae/verify`. Needs no API key.
#'
#' @inheritParams verdifax_health
#' @param bundle A named list of the proof bundle fields.
#'
#' @return Parsed API response list with `verified`.
#'
#' @export
verdifax_dcae_verify <- function(client, bundle) {
  .send(client, "POST", "/dcae/verify", bundle)
}


# ── Attestation receipts ────────────────────────────────────────────────────

#' List attestation receipts, newest first.
#'
#' @inheritParams verdifax_list_runs
#'
#' @return Parsed API response list with `count`, `limit`, `offset` and
#'   `attestations`.
#'
#' @export
verdifax_list_attestations <- function(client, limit = NULL, offset = NULL) {
  .perform(.get(client, "/attestations", .query(limit = limit, offset = offset)))
}

#' Fetch one attestation receipt.
#'
#' @inheritParams verdifax_health
#' @param attestation_id The receipt's ID.
#'
#' @return Parsed API response list.
#'
#' @export
verdifax_get_attestation <- function(client, attestation_id) {
  .perform(.get(client, paste0("/attestations/", .require_id(attestation_id, "attestation_id"))))
}


# ── Sealed artifacts ────────────────────────────────────────────────────────

#' The sealed AllowToken of an admitted run.
#'
#' @inheritParams verdifax_verify_run
#'
#' @return Parsed API response list.
#'
#' @export
verdifax_get_allow_token <- function(client, run_id) {
  .perform(.get(client, .run_path(run_id, "/allow-token")))
}

#' The sealed DenyReceipt of a `pepg_deny` run.
#'
#' @inheritParams verdifax_verify_run
#'
#' @return Parsed API response list.
#'
#' @export
verdifax_get_deny_receipt <- function(client, run_id) {
  .perform(.get(client, .run_path(run_id, "/deny-receipt")))
}

#' The sealed CCVHaltReceipt of a `ccv_halt` run.
#'
#' @inheritParams verdifax_verify_run
#'
#' @return Parsed API response list.
#'
#' @export
verdifax_get_ccv_halt_receipt <- function(client, run_id) {
  .perform(.get(client, .run_path(run_id, "/ccv-halt-receipt")))
}

#' The sealed MACCHaltReceipt of a `macc_halt` run.
#'
#' @inheritParams verdifax_verify_run
#'
#' @return Parsed API response list.
#'
#' @export
verdifax_get_macc_halt_receipt <- function(client, run_id) {
  .perform(.get(client, .run_path(run_id, "/macc-halt-receipt")))
}

#' The sealed halt receipt of a run the AIVP stage stopped.
#'
#' @inheritParams verdifax_verify_run
#'
#' @return Parsed API response list.
#'
#' @export
verdifax_get_aivp_t4_halt_receipt <- function(client, run_id) {
  .perform(.get(client, .run_path(run_id, "/aivp-t4-halt-receipt")))
}

#' The sealed AttestationGapReceipt of an `attestation_gap` run.
#'
#' @inheritParams verdifax_verify_run
#'
#' @return Parsed API response list.
#'
#' @export
verdifax_get_attestation_gap_receipt <- function(client, run_id) {
  .perform(.get(client, .run_path(run_id, "/attestation-gap-receipt")))
}

#' The CES audit record of a run.
#'
#' @inheritParams verdifax_verify_run
#'
#' @return Parsed API response list.
#'
#' @export
verdifax_get_ces_audit_record <- function(client, run_id) {
  .perform(.get(client, .run_path(run_id, "/ces-audit-record")))
}

#' The audit report for a run, as JSON.
#'
#' @inheritParams verdifax_verify_run
#'
#' @return The parsed `report` of the response.
#'
#' @export
verdifax_get_run_report <- function(client, run_id) {
  .perform(.get(client, .run_path(run_id, "/report")))[["report"]]
}

#' The audit PDF for a run.
#'
#' @inheritParams verdifax_verify_run
#' @param format One of `"brief"`, `"auditor"`, `"legal"` or
#'   `"comprehensive"`.
#'
#' @return A raw vector of the PDF bytes. Save it with `writeBin()`.
#'
#' @export
verdifax_download_audit_pdf <- function(client, run_id, format = "comprehensive") {
  req <- .get(client, .run_path(run_id, "/report.pdf"), .query(format = format))
  httr2::resp_body_raw(httr2::req_perform(req))
}

#' The run's sealed audit bundle as the exact JSON text the server sent.
#'
#' Save it with `writeLines()` and check it with `verdifax-verify`. It
#' is not parsed: R reads JSON numbers as doubles, which would round a
#' number above 2^53, and the recomputed hash would stop matching.
#'
#' @inheritParams verdifax_verify_run
#'
#' @return The JSON text as a single string.
#'
#' @export
verdifax_get_run_artifacts <- function(client, run_id) {
  .get_body_text(client, .run_path(run_id, "/artifacts"))
}

#' The public audit bundle of a record published by run id.
#'
#' Needs no API key.
#'
#' @inheritParams verdifax_verify_run
#'
#' @return The exact JSON text the server sent, as a single string.
#'
#' @export
verdifax_get_public_bundle <- function(client, run_id) {
  .get_body_text(client, .run_path(run_id, "/bundle.json"))
}

#' The public audit bundle a share token points to.
#'
#' Needs no API key.
#'
#' @inheritParams verdifax_health
#' @param token The share token.
#'
#' @return The exact JSON text the server sent, as a single string.
#'
#' @export
verdifax_get_public_bundle_by_token <- function(client, token) {
  if (!is.character(token) || length(token) != 1 || is.na(token) || !nzchar(token)) {
    stop("token is required", call. = FALSE)
  }
  # req_url_path() would escape the escaped token a second time.
  escaped <- utils::URLencode(token, reserved = TRUE)
  req <- .get(client, "/public/runs")
  req <- httr2::req_url(req, paste0(client$base_url, "/public/runs/", escaped, "/bundle.json"))
  httr2::resp_body_string(httr2::req_perform(req))
}

#' The CRES deletion receipts bound to a run.
#'
#' @inheritParams verdifax_verify_run
#'
#' @return A list of receipts.
#'
#' @export
verdifax_list_deletion_receipts <- function(client, run_id) {
  .perform(.get(client, .run_path(run_id, "/deletion-receipts")))[["receipts"]]
}


# ── Admin ───────────────────────────────────────────────────────────────────

#' Create an API key.
#'
#' @inheritParams verdifax_health
#' @param name The key's name.
#'
#' @return Parsed API response list. It holds the secret once.
#'
#' @export
verdifax_admin_create_key <- function(client, name) {
  if (!is.character(name) || length(name) != 1 || is.na(name) || !nzchar(name)) {
    stop("name is required", call. = FALSE)
  }
  .send(client, "POST", "/admin/keys", list(name = name))
}

#' List the API keys in the deployment, without their secrets.
#'
#' @inheritParams verdifax_health
#'
#' @return A list of keys.
#'
#' @export
verdifax_admin_list_keys <- function(client) {
  .perform(.get(client, "/admin/keys"))[["keys"]]
}

#' Revoke an API key by id.
#'
#' @inheritParams verdifax_health
#' @param key_id The key's id.
#'
#' @return `NULL`, invisibly.
#'
#' @export
verdifax_admin_revoke_key <- function(client, key_id) {
  .send(client, "DELETE", paste0("/admin/keys/", .require_id(key_id, "key_id")))
  invisible(NULL)
}

#' Shred one field and return its sealed deletion receipt.
#'
#' @inheritParams verdifax_verify_run
#' @param field_path The field's dotted path.
#' @param ciphertext_hash 64-char lowercase hex hash of the sealed
#'   ciphertext.
#' @param dsar_reference Optional reference for the originating request.
#'
#' @return The parsed `deletion_receipt` of the response.
#'
#' @export
verdifax_admin_erase <- function(client,
                                 run_id,
                                 field_path,
                                 ciphertext_hash,
                                 dsar_reference = NULL) {
  .require_id(run_id, "run_id")
  if (!is.character(field_path) || length(field_path) != 1 || !nzchar(field_path)) {
    stop("field_path is required", call. = FALSE)
  }
  verdifax_validate_hex64(ciphertext_hash, "ciphertext_hash")
  body <- list(run_id = run_id, field_path = field_path, ciphertext_hash = ciphertext_hash)
  body$dsar_reference <- dsar_reference
  .send(client, "POST", "/admin/erase", body)[["deletion_receipt"]]
}


# ── Provider helpers ────────────────────────────────────────────────────────

# One JSON string with only the escapes JSON requires, the same in all
# four SDKs. jsonlite is not used here so that its escaping choices cannot
# change the bytes.
.canonical_json_string <- function(value) {
  text <- enc2utf8(value)
  if (!validUTF8(text)) {
    stop("provider payload text is not valid UTF-8", call. = FALSE)
  }
  points <- utf8ToInt(text)
  pieces <- vapply(points, function(point) {
    switch(as.character(point),
      "34" = "\\\"",
      "92" = "\\\\",
      "8" = "\\b",
      "12" = "\\f",
      "10" = "\\n",
      "13" = "\\r",
      "9" = "\\t",
      if (point < 32) sprintf("\\u%04x", point) else intToUtf8(point)
    )
  }, character(1))
  enc2utf8(paste0("\"", paste(pieces, collapse = ""), "\""))
}

#' The payload the provider helpers attest.
#'
#' Canonical JSON with sorted keys, no extra whitespace and UTF-8 text,
#' exactly `{"prompt":...,"provider":...,"response":...}`. All four SDKs
#' produce the same bytes, and a shared test vector holds them to it.
#'
#' @param provider The provider's name, `"anthropic"` or `"openai"`.
#' @param prompt The prompt text.
#' @param response The response text.
#'
#' @return The payload as JSON text.
#'
#' @export
verdifax_format_provider_payload <- function(provider, prompt, response) {
  paste0(
    "{\"prompt\":", .canonical_json_string(prompt),
    ",\"provider\":", .canonical_json_string(provider),
    ",\"response\":", .canonical_json_string(response),
    "}"
  )
}

.attest_provider_response <- function(client, provider, prompt, response, program_id, route_id,
                                      registry_record_hash, govern) {
  if (!is.character(response) || length(response) != 1 || !nzchar(response)) {
    stop("response is required for attestation", call. = FALSE)
  }
  verdifax_attest(
    client = client,
    payload = verdifax_format_provider_payload(provider, prompt, response),
    program_id = program_id,
    route_id = route_id,
    registry_record_hash = registry_record_hash,
    ai_output_text = if (isTRUE(govern)) response else NULL,
    attested_context = list(actor_role = "ai_assistant", model_provider = provider)
  )
}

#' Attest an Anthropic Claude prompt and response.
#'
#' Attests the two as one payload, with provider `"anthropic"`.
#'
#' @inheritParams verdifax_attest
#' @param prompt The prompt text.
#' @param response The response text.
#' @param govern When `TRUE`, also send the response text for the AIVP
#'   review, which runs on Anthropic in production. Defaults to `FALSE`,
#'   so the text goes for review only when you ask.
#'
#' @return Parsed API response list, as from `verdifax_attest()`.
#'
#' @export
verdifax_attest_claude_response <- function(client, prompt, response, program_id, route_id,
                                            registry_record_hash, govern = FALSE) {
  .attest_provider_response(
    client, "anthropic", prompt, response, program_id, route_id, registry_record_hash, govern
  )
}

#' Attest an OpenAI prompt and response.
#'
#' Attests the two as one payload, with provider `"openai"`.
#'
#' @inheritParams verdifax_attest_claude_response
#'
#' @return Parsed API response list, as from `verdifax_attest()`.
#'
#' @export
verdifax_attest_openai_response <- function(client, prompt, response, program_id, route_id,
                                            registry_record_hash, govern = FALSE) {
  .attest_provider_response(
    client, "openai", prompt, response, program_id, route_id, registry_record_hash, govern
  )
}


# ── Signing without sending ─────────────────────────────────────────────────

#' Build a request signature without sending anything.
#'
#' A client with a `signing_key` does this itself. Needs the `sodium`
#' package.
#'
#' @param signing_key The 32 raw bytes of an Ed25519 private key.
#' @param body A named list holding the request's `payload_text` or
#'   `payload`, `program_id`, `route_id` and `registry_record_hash`.
#' @param signed_at Optional RFC 3339 UTC time. Defaults to now.
#' @param nonce Optional 32 hex characters. Defaults to fresh random
#'   bytes. A nonce the server has already seen is refused.
#'
#' @return A list with `signature`, `signed_at` and `nonce`.
#'
#' @export
verdifax_sign_request <- function(signing_key, body, signed_at = NULL, nonce = NULL) {
  .request_signature(.request_signer(signing_key), body, signed_at, nonce)
}

#' Build the body of `POST /keys/request-key` without sending it.
#'
#' Needs the `sodium` package.
#'
#' @param signing_key The 32 raw bytes of an Ed25519 private key.
#'
#' @return A list with `public_key` and `proof`.
#'
#' @export
verdifax_request_key_registration_body <- function(signing_key) {
  .request_key_body(.request_signer(signing_key))
}

#' The bytes a request signature signs.
#'
#' @param payload_hash The SHA-256 of the payload as hex.
#' @param program_id The program ID.
#' @param route_id The route identifier.
#' @param registry_record_hash The record hash.
#' @param signed_at The RFC 3339 UTC time.
#' @param nonce The nonce as hex.
#'
#' @return A raw vector, with the fields joined by single zero bytes.
#'
#' @export
verdifax_request_signature_preimage <- function(payload_hash, program_id, route_id,
                                                registry_record_hash, signed_at, nonce) {
  .join_with_zero(list(
    .REQUEST_SIGNATURE_FORM, payload_hash, program_id, route_id,
    registry_record_hash, signed_at, nonce
  ))
}

# ----------------------------------------------------------------------------
# verdifax, run retrieval, evidence export and batch runs
# ----------------------------------------------------------------------------

.BATCH_MAX_ROWS <- 1000L
.HEADER_EXPORT_TOTAL <- "X-Verdifax-Total"
.HEADER_EXPORT_TRUNCATED <- "X-Verdifax-Truncated"


# ── Requests ────────────────────────────────────────────────────────────────

# Drops the unset values, so the server applies its defaults. A number
# is written out in full, because R would otherwise send 1e+05.
.query <- function(...) {
  values <- list(...)
  values <- values[!vapply(values, function(v) is.null(v) || identical(v, ""), logical(1))]
  lapply(values, function(v) {
    if (is.numeric(v)) format(v, scientific = FALSE, trim = TRUE) else v
  })
}

.run_path <- function(run_id, suffix = "") {
  if (!is.numeric(run_id) || length(run_id) != 1 || is.na(run_id) ||
      run_id <= 0 || run_id != floor(run_id)) {
    stop("run_id must be a positive whole number", call. = FALSE)
  }
  paste0("/runs/", format(run_id, scientific = FALSE, trim = TRUE), suffix)
}

.get <- function(client, path, query = NULL) {
  req <- .build_request(client, path, NULL, method = "GET", query = query)
  httr2::req_error(req, body = .error_detail)
}


# ── Runs ────────────────────────────────────────────────────────────────────

#' Ask the server to recompute a recorded run's manifest hash.
#'
#' Calls `GET /runs/{id}/verify`. The server recomputes the manifest
#' hash from the run's stored fields and compares it with the hash it
#' recorded. It does not re-run the pipeline, and it is a check
#' performed by Verdifax. For an independent offline check of the
#' sealed audit bundle, use the open-source `verdifax-verify` CLI.
#'
#' @param client A client handle from `verdifax_client()`.
#' @param run_id The server-side run ID.
#'
#' @return Parsed API response list with `verified`, `manifest_hash`
#'   and `recomputed_hash`. A run recorded as a stage error has no
#'   stored manifest, so `verified` is `FALSE` with a `reason`.
#'
#' @export
verdifax_verify_run <- function(client, run_id) {
  .perform(.get(client, .run_path(run_id, "/verify")))
}

#' Fetch one run.
#'
#' @inheritParams verdifax_verify_run
#'
#' @return Parsed API response list with the run's fields and, when
#'   the server stored one, `manifest`.
#'
#' @export
verdifax_get_run <- function(client, run_id) {
  .perform(.get(client, .run_path(run_id)))
}

#' List this key's runs.
#'
#' @param client A client handle from `verdifax_client()`.
#' @param limit Optional page size. The server caps it at 500.
#' @param offset Optional number of rows to skip.
#'
#' @return Parsed API response list with `total`, `limit`, `offset`
#'   and `runs`.
#'
#' @export
verdifax_list_runs <- function(client, limit = NULL, offset = NULL) {
  .perform(.get(client, "/runs", .query(limit = limit, offset = offset)))
}

#' Search this key's runs.
#'
#' @inheritParams verdifax_list_runs
#' @param manifest_hash Optional. Matches a hash that starts with this
#'   value.
#' @param program_id Optional program ID.
#' @param route_id Optional route identifier.
#' @param status Optional run status, for example `"ok"`.
#' @param from,to Optional RFC 3339 times. The server ignores one it
#'   cannot parse here, unlike `verdifax_export_runs()`, which refuses
#'   it.
#'
#' @return Parsed API response list with `total`, `limit`, `offset`
#'   and `runs`.
#'
#' @export
verdifax_search_runs <- function(client,
                                 manifest_hash = NULL,
                                 program_id = NULL,
                                 route_id = NULL,
                                 status = NULL,
                                 from = NULL,
                                 to = NULL,
                                 limit = NULL,
                                 offset = NULL) {
  query <- .query(
    manifest_hash = manifest_hash,
    program_id = program_id,
    route_id = route_id,
    status = status,
    from = from,
    to = to,
    limit = limit,
    offset = offset
  )
  .perform(.get(client, "/runs/search", query))
}


# ── Evidence export ─────────────────────────────────────────────────────────

#' Export the runs the server holds for this key in a period.
#'
#' Failures are included, up to 10,000 rows. `truncated` is `TRUE` when
#' the period holds more. The list states what was stored, not a
#' verdict, and a call that never reached Verdifax cannot appear in it.
#'
#' @param client A client handle from `verdifax_client()`.
#' @param from Optional RFC 3339 time, inclusive.
#' @param to Optional RFC 3339 time, exclusive. Defaults to the time of
#'   the request.
#' @param job_id Optional job. Limits the export to that job's runs.
#'
#' @return Parsed API response list with `to`, `total`, `returned`,
#'   `truncated`, `by_status` and `runs`. New rows hold `anchor_source`,
#'   `job_id` and `step_id`.
#'
#' @export
verdifax_export_runs <- function(client, from = NULL, to = NULL, job_id = NULL) {
  if (!is.null(job_id)) {
    .check_job_name(job_id, "job_id")
  }
  query <- .query(from = from, to = to, job_id = job_id, format = "json")
  .perform(.get(client, "/runs/export", query))
}

#' Export the same rows as `verdifax_export_runs()` as CSV.
#'
#' `total` and `truncated` come from the response headers. Check
#' `truncated`: when `TRUE`, the CSV is missing rows for the period. The
#' call stops with an error when the server does not send those headers,
#' so that a cut-off export cannot pass for a complete one.
#'
#' @inheritParams verdifax_export_runs
#'
#' @return A list with `csv`, the CSV text as a single string, `total`,
#'   the runs held for the period, and `truncated`.
#'
#' @export
verdifax_export_runs_csv <- function(client, from = NULL, to = NULL, job_id = NULL) {
  if (!is.null(job_id)) {
    .check_job_name(job_id, "job_id")
  }
  query <- .query(from = from, to = to, job_id = job_id, format = "csv")
  resp <- httr2::req_perform(.get(client, "/runs/export", query))
  total <- httr2::resp_header(resp, .HEADER_EXPORT_TOTAL)
  truncated <- httr2::resp_header(resp, .HEADER_EXPORT_TRUNCATED)
  if (is.null(total) || !grepl("^[0-9]+$", total) ||
      is.null(truncated) || !truncated %in% c("true", "false")) {
    stop(
      "the server did not report ", .HEADER_EXPORT_TOTAL, " and ",
      .HEADER_EXPORT_TRUNCATED,
      ", so this CSV may be cut off; use verdifax_export_runs() instead",
      call. = FALSE
    )
  }
  list(
    csv = httr2::resp_body_string(resp),
    total = as.numeric(total),
    truncated = identical(truncated, "true")
  )
}


# ── Batch runs ──────────────────────────────────────────────────────────────

.batch_row <- function(row) {
  if (!is.list(row) || is.null(names(row)) || any(!nzchar(names(row)))) {
    stop(
      "each run must be a named list with the arguments of verdifax_attest()",
      call. = FALSE
    )
  }
  # The server ignores a field it does not know, so a misspelt one would be
  # dropped with no error.
  unknown <- setdiff(names(row), .EXECUTE_FIELDS)
  if (length(unknown) > 0) {
    stop("a run has an unknown field: ", paste(unknown, collapse = ", "), call. = FALSE)
  }
  known <- c(
    "payload", "program_id", "route_id", "registry_record_hash",
    "reproducibility_context", "ai_output_text", "attested_context",
    "request_substance", "authorization_chain", "regulatory_scaffolding",
    "causal_graph", "job", "policy_context", "expected_policy_hash"
  )
  body <- .execute_fields(
    payload = row[["payload"]],
    program_id = row[["program_id"]],
    route_id = row[["route_id"]],
    registry_record_hash = row[["registry_record_hash"]],
    reproducibility_context = row[["reproducibility_context"]],
    ai_output_text = row[["ai_output_text"]],
    attested_context = row[["attested_context"]],
    request_substance = row[["request_substance"]],
    authorization_chain = row[["authorization_chain"]],
    regulatory_scaffolding = row[["regulatory_scaffolding"]],
    causal_graph = row[["causal_graph"]],
    job = row[["job"]],
    policy_context = row[["policy_context"]],
    expected_policy_hash = row[["expected_policy_hash"]]
  )
  # A NULL element would reach the wire as {}, and the server would
  # refuse the whole batch instead of this row.
  body <- body[!vapply(body, is.null, logical(1))]
  c(body, row[setdiff(names(row), known)])
}

# Each result gets the text its row signed. Results line up with rows by
# position. A result's index is not used, because the server leaves it 0
# on a row it could not read.
.add_signed_requests <- function(result, rows) {
  results <- result[["results"]]
  if (length(results) != length(rows)) {
    return(result)
  }
  for (i in seq_along(rows)) {
    results[[i]]$signed_request <- rows[[i]][["signed_request"]]
  }
  result$results <- results
  result
}

#' Send up to 1,000 runs in one request.
#'
#' Calls `POST /execute/batch`. The rows' values are not checked here:
#' the server reports a bad row in that row's result, and a failed row
#' does not stop the call. The exceptions stop the call before anything is
#' sent: a field name the server does not know, in a row or in its
#' `attested_context`, and a bad `job` block, `policy_context` or
#' `expected_policy_hash`. With a `signing_key`, each row carries
#' its own signature and nonce, and its result holds `signed_request`.
#'
#' This is one POST and it is never retried. After a timeout the server
#' may have run some or all of the rows.
#'
#' @param client A client handle from `verdifax_client()`.
#' @param runs A list of rows. Each row is a named list with the
#'   argument names of `verdifax_attest()`.
#'
#' @return Parsed API response list with `total`, `successful`,
#'   `failed`, `duration_ms` and `results`. Each result holds
#'   `record_hash` when the row left a record.
#'
#' @export
verdifax_execute_batch <- function(client, runs) {
  if (!is.list(runs) || !is.null(names(runs))) {
    stop("runs must be an unnamed list of rows", call. = FALSE)
  }
  if (length(runs) == 0) {
    stop("verdifax_execute_batch needs at least one run", call. = FALSE)
  }
  if (length(runs) > .BATCH_MAX_ROWS) {
    stop(
      "verdifax_execute_batch accepts at most ", .BATCH_MAX_ROWS,
      " runs (got ", length(runs), ")",
      call. = FALSE
    )
  }
  rows <- lapply(runs, function(row) .attach_signature(client, .batch_row(row)))
  req <- .build_request(client, "/execute/batch", list(runs = rows))
  .add_signed_requests(.perform(httr2::req_error(req, body = .error_detail)), rows)
}

#' The most rows one batch can hold.
#'
#' @return The row limit of `verdifax_execute_batch()`.
#' @export
verdifax_max_batch_rows <- function() {
  .BATCH_MAX_ROWS
}

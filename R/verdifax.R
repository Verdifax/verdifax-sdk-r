# ----------------------------------------------------------------------------
# verdifax — R SDK for the Verdifax cryptographic attestation pipeline
# ----------------------------------------------------------------------------
#
# Four exported functions:
#
#   verdifax_client(base_url, api_key, timeout)
#     Construct a client handle. Reads VERDIFAX_API_URL and
#     VERDIFAX_API_KEY from environment by default. The returned
#     list is passed to verdifax_attest() and verdifax_verify_determinism().
#
#   verdifax_capture_environment(declared_seeds = list(),
#                                include_dependencies = TRUE,
#                                include_git = TRUE,
#                                include_container = TRUE)
#     Best-effort auto-detection of the current R runtime
#     environment. Returns a list whose names match the orchestrator's
#     ReproducibilityContext JSON contract (container_image_hash,
#     runtime_name, runtime_version, pinned_dependencies,
#     git_commit_sha, random_seeds, platform).
#
#   verdifax_attest(client, payload, program_id, route_id,
#                   registry_record_hash,
#                   reproducibility_context = NULL,
#                   ai_output_text = NULL)
#     Attest a payload via POST /execute and return the parsed
#     response list (run_id, manifest_hash, etc.).
#
#   verdifax_verify_determinism(client, payload, program_id, route_id,
#                               registry_record_hash,
#                               reproducibility_context = NULL,
#                               ai_output_text = NULL)
#     Wrap POST /execute/verify-determinism. Runs the payload twice
#     and returns a list with deterministic flag, both run records,
#     and the comparison diff.
#
# All failures from auto-detection are silently swallowed and the
# corresponding field is left NULL. The orchestrator records NULL as
# "not declared" rather than fabricating a claim.
#
# Dependencies (declared in DESCRIPTION):
#   httr2 (>= 1.0.0)
#   jsonlite (>= 1.8.0)

# ── Module-level constants ──────────────────────────────────────────────────

.DEFAULT_BASE_URL <- "http://localhost:9090"
.DEFAULT_TIMEOUT_SEC <- 30


# ── Client ──────────────────────────────────────────────────────────────────

#' Construct a Verdifax client handle.
#'
#' @param base_url Base URL of the Verdifax API. Falls back to the
#'   environment variable `VERDIFAX_API_URL`, then to
#'   `http://localhost:9090`. Trailing slashes are stripped.
#' @param api_key Optional API key sent as the `X-Verdifax-Key`
#'   header. Falls back to the environment variable
#'   `VERDIFAX_API_KEY`.
#' @param timeout Request timeout in seconds. Defaults to 30.
#'
#' @return A list with named elements (`base_url`, `api_key`,
#'   `timeout`) suitable to pass to `verdifax_attest()` or
#'   `verdifax_verify_determinism()`.
#'
#' @export
verdifax_client <- function(base_url = NULL,
                            api_key = NULL,
                            timeout = .DEFAULT_TIMEOUT_SEC) {
  resolved_url <- base_url %||% Sys.getenv("VERDIFAX_API_URL", unset = NA)
  if (is.na(resolved_url) || identical(resolved_url, "")) {
    resolved_url <- .DEFAULT_BASE_URL
  }
  resolved_url <- sub("/+$", "", resolved_url)

  resolved_key <- api_key %||% Sys.getenv("VERDIFAX_API_KEY", unset = NA)
  if (is.na(resolved_key) || identical(resolved_key, "")) {
    resolved_key <- NULL
  }

  list(
    base_url = resolved_url,
    api_key = resolved_key,
    timeout = as.numeric(timeout)
  )
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
    seeds_list <- vapply(
      keys,
      function(k) paste0(k, "=", as.character(declared_seeds[[k]])),
      character(1)
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

  # Drop NULL entries — jsonlite will skip them, but explicit removal
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

.build_request <- function(client, path, body) {
  req <- httr2::request(client$base_url)
  req <- httr2::req_url_path(req, path)
  req <- httr2::req_method(req, "POST")
  req <- httr2::req_headers(
    req,
    "Content-Type" = "application/json",
    "Accept" = "application/json",
    "User-Agent" = paste0(
      "verdifax-r/", utils::packageVersion("verdifax")
    )
  )
  if (!is.null(client$api_key)) {
    req <- httr2::req_headers(req, "X-Verdifax-Key" = client$api_key)
  }
  req <- httr2::req_body_json(req, body, auto_unbox = TRUE)
  req <- httr2::req_timeout(req, client$timeout)
  req
}

.perform <- function(req) {
  resp <- httr2::req_perform(req)
  body <- httr2::resp_body_string(resp)
  parsed <- jsonlite::fromJSON(body, simplifyVector = FALSE)
  parsed
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
#' @param ai_output_text Optional AI output text for AIVP-T4
#'   governance.
#'
#' @return Parsed API response list with `ok`, `run_id`,
#'   `manifest`, etc.
#'
#' @export
verdifax_attest <- function(client,
                            payload,
                            program_id,
                            route_id,
                            registry_record_hash,
                            reproducibility_context = NULL,
                            ai_output_text = NULL) {
  body <- .build_execute_body(
    payload = payload,
    program_id = program_id,
    route_id = route_id,
    registry_record_hash = registry_record_hash,
    reproducibility_context = reproducibility_context,
    ai_output_text = ai_output_text
  )
  req <- .build_request(client, "/execute", body)
  .perform(req)
}


# ── Determinism verification ────────────────────────────────────────────────

#' Verify the pipeline produces byte-identical evidence on replay.
#'
#' Runs the same payload through the Verdifax pipeline twice in
#' immediate succession (server-side pinned clock) and returns the
#' comparison summary.
#'
#' The top-level `deterministic` flag is grounded on manifest hash
#' equality — the canonical seal of the pipeline output. Bundle hash
#' differences are surfaced in `diff$differing_fields` as
#' informational metadata (server-observed timing variation).
#'
#' @inheritParams verdifax_attest
#'
#' @return Parsed API response list with `deterministic`, `first`,
#'   `second`, and `diff` fields.
#'
#' @export
verdifax_verify_determinism <- function(client,
                                        payload,
                                        program_id,
                                        route_id,
                                        registry_record_hash,
                                        reproducibility_context = NULL,
                                        ai_output_text = NULL) {
  body <- .build_execute_body(
    payload = payload,
    program_id = program_id,
    route_id = route_id,
    registry_record_hash = registry_record_hash,
    reproducibility_context = reproducibility_context,
    ai_output_text = ai_output_text
  )
  req <- .build_request(client, "/execute/verify-determinism", body)
  .perform(req)
}


# ── Internal: request body builder ──────────────────────────────────────────

.build_execute_body <- function(payload,
                                program_id,
                                route_id,
                                registry_record_hash,
                                reproducibility_context = NULL,
                                ai_output_text = NULL) {
  .validate_hex64(program_id, "program_id")
  .validate_hex64(registry_record_hash, "registry_record_hash")
  if (!nzchar(route_id)) {
    stop("route_id must be a non-empty string")
  }

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
  } else {
    stop("payload must be character or raw")
  }

  if (!is.null(ai_output_text) && nzchar(ai_output_text)) {
    body$ai_output_text <- ai_output_text
  }

  if (!is.null(reproducibility_context)) {
    # Filter NULL entries before sending; orchestrator handles
    # missing fields as "not declared".
    ctx <- reproducibility_context[!vapply(reproducibility_context, is.null, logical(1))]
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
    if (length(ctx) > 0) {
      body$reproducibility_context <- ctx
    }
  }

  body
}


# ── Validation helpers ──────────────────────────────────────────────────────

.validate_hex64 <- function(value, field_name) {
  if (!is.character(value) || length(value) != 1 || is.na(value)) {
    stop(field_name, " must be a non-NA character scalar")
  }
  if (nchar(value) != 64 || !grepl("^[0-9a-f]{64}$", tolower(value))) {
    stop(field_name, " must be 64 lowercase hex characters")
  }
  invisible(TRUE)
}


# ── Utilities ───────────────────────────────────────────────────────────────

# Null-coalescing operator: returns the right side if the left is NULL.
`%||%` <- function(x, y) if (is.null(x)) y else x

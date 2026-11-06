# ----------------------------------------------------------------------------
# verdifax, job blocks and the job helper
# ----------------------------------------------------------------------------
#
# A job is a map of records. Each step names the records it directly follows,
# so work can split into branches and join again.

.JOB_BLOCK_FIELDS <- c(
  "job_id", "step_id", "previous_record_hashes", "external_previous", "final"
)

# perl = TRUE and \z because `$` would accept a trailing newline, and because
# a bracket range in the default engine can depend on the locale.
.check_job_name <- function(value, name) {
  valid <- is.character(value) && length(value) == 1 && !is.na(value) &&
    validUTF8(value) && grepl("^[A-Za-z0-9._:-]{1,128}\\z", value, perl = TRUE)
  if (!valid) {
    stop(
      name, " must be 1 to 128 letters, digits, dots, underscores, colons or dashes",
      call. = FALSE
    )
  }
  invisible(TRUE)
}

# A character vector or a list of single strings. Checked before unlist(),
# which would turn a number in a list into a string.
.is_string_list <- function(values) {
  is.character(values) || (is.list(values) && all(vapply(
    values, function(value) is.character(value) && length(value) == 1, logical(1)
  )))
}

# Sorted in byte order with no repeats, as the server requires. sort() would
# otherwise follow the locale. A list, unlike a vector, stays a JSON array
# when it holds one hash. NULL leaves an empty list out of the block.
.job_hash_list <- function(hashes, name) {
  if (is.null(hashes)) {
    return(NULL)
  }
  values <- unlist(hashes)
  if (!.is_string_list(hashes) || anyNA(values)) {
    stop(name, " must be a list of hash strings", call. = FALSE)
  }
  if (length(values) == 0) {
    return(NULL)
  }
  as.list(sort(unique(values), method = "radix"))
}

.job_block <- function(job) {
  if (!is.list(job) || is.null(names(job))) {
    stop("job must be a named list", call. = FALSE)
  }
  unknown <- setdiff(names(job), .JOB_BLOCK_FIELDS)
  if (length(unknown) > 0) {
    stop("job has an unknown field: ", paste(unknown, collapse = ", "), call. = FALSE)
  }
  if (anyDuplicated(names(job)) > 0) {
    stop("job names a field twice", call. = FALSE)
  }
  .check_job_name(job[["job_id"]], "job_id")
  .check_job_name(job[["step_id"]], "step_id")
  final <- job[["final"]]
  if (!is.null(final) && (!is.logical(final) || length(final) != 1 || is.na(final))) {
    stop("job final must be TRUE or FALSE", call. = FALSE)
  }
  block <- list(job_id = job[["job_id"]], step_id = job[["step_id"]])
  block$previous_record_hashes <- .job_hash_list(
    job[["previous_record_hashes"]], "previous_record_hashes"
  )
  block$external_previous <- .job_hash_list(job[["external_previous"]], "external_previous")
  if (isTRUE(final)) {
    block$final <- TRUE
  }
  block
}

#' Start a job, a map of the steps of one piece of work.
#'
#' Run each step with `verdifax_job_step()`. `job$record_hashes` is a named
#' character vector from step id to record hash, and it includes refused
#' and halted steps. With a signing key, `job$signed_requests` holds each
#' of those steps' signed text the same way, to keep for
#' `verdifax-verify --request FILE`.
#'
#' @param client A client handle from `verdifax_client()`.
#' @param job_id 1 to 128 letters, digits, dots, underscores, colons or
#'   dashes.
#'
#' @return A job object. It is an environment, so each step updates it in
#'   place.
#'
#' @export
verdifax_job <- function(client, job_id) {
  .check_job_name(job_id, "job_id")
  job <- new.env(parent = emptyenv())
  job$client <- client
  job$job_id <- job_id
  job$record_hashes <- character(0)
  job$signed_requests <- character(0)
  job$last_step <- NULL
  class(job) <- "verdifax_job"
  job
}

# The step ids in `after` as record hashes. NULL means the step run just
# before this one, and an empty vector or list starts another root step.
.job_previous <- function(job, after) {
  if (is.null(after)) {
    after <- job$last_step
  }
  after <- unlist(after)
  if (length(after) == 0) {
    return(NULL)
  }
  if (!is.character(after)) {
    stop("after must name step ids in this job", call. = FALSE)
  }
  unknown <- setdiff(after, names(job$record_hashes))
  if (length(unknown) > 0) {
    stop(
      "after names a step that is not in this job: ",
      paste(unknown, collapse = ", "),
      call. = FALSE
    )
  }
  unname(job$record_hashes[after])
}

.record_job_step <- function(job, step_id, record_hash, signed_request) {
  job$record_hashes[[step_id]] <- record_hash
  if (!is.null(signed_request)) {
    job$signed_requests[[step_id]] <- signed_request
  }
  job$last_step <- step_id
  invisible(job)
}

# Names are matched exactly, so a typo cannot reach verdifax_attest(), where
# partial matching could accept it, and cannot leave `after` at its default.
# The helper sets client and job itself. Unnamed values pass by position.
.check_step_arguments <- function(arguments) {
  allowed <- setdiff(names(formals(verdifax_attest)), c("client", "job"))
  unknown <- setdiff(names(arguments), c("", allowed))
  if (length(unknown) > 0) {
    stop(
      "verdifax_job_step has an unknown argument: ",
      paste(unknown, collapse = ", "),
      call. = FALSE
    )
  }
  invisible(TRUE)
}

# The hash a completed step links by. POST /execute holds the manifest hash
# inside `manifest`, not beside it.
.step_record_hash <- function(result) {
  result[["record_hash"]] %||% result[["manifest_hash"]] %||%
    result[["manifest"]][["ManifestHash"]]
}

#' Run one step of a job.
#'
#' Attests the step with `verdifax_attest()` and records its `record_hash`
#' and, when signed, its `signed_request`. A refused or halted step is
#' recorded too, from the error, and then the same error stops the call, so
#' a later step can still name that step in `after`. A call that left no record, such as a timeout, is not recorded,
#' and the step before it stays the one the next step follows.
#'
#' @param job A job from `verdifax_job()`.
#' @param step_id 1 to 128 letters, digits, dots, underscores, colons or
#'   dashes.
#' @param ... The arguments of `verdifax_attest()`: `payload`, `program_id`,
#'   `route_id`, `registry_record_hash` and the optional ones. Any other name,
#'   including `job`, is refused before anything is sent, so a typo such as
#'   `afer` cannot silently use the default link.
#' @param after Step ids in this job that this step directly follows. By
#'   default, the step run just before this one through this job, or nothing
#'   for the first step. `character(0)` or `list()` starts another root step.
#'   A step id this job has not recorded is refused before anything is sent.
#' @param external_previous Optional record hashes from outside this job
#'   that this step follows.
#' @param final `TRUE` when this step closes the job.
#'
#' @return Parsed API response list, as from `verdifax_attest()`.
#'
#' @export
verdifax_job_step <- function(job,
                              step_id,
                              ...,
                              after = NULL,
                              external_previous = NULL,
                              final = FALSE) {
  if (!inherits(job, "verdifax_job")) {
    stop("job must come from verdifax_job()", call. = FALSE)
  }
  .check_job_name(step_id, "step_id")
  .check_step_arguments(list(...))
  link <- list(
    job_id = job$job_id,
    step_id = step_id,
    previous_record_hashes = .job_previous(job, after),
    external_previous = external_previous,
    final = final
  )
  result <- withCallingHandlers(
    verdifax_attest(job$client, ..., job = link),
    httr2_http = function(error) {
      if (!is.null(error$record_hash)) {
        .record_job_step(job, step_id, error$record_hash, error$signed_request)
      }
    }
  )
  record_hash <- .step_record_hash(result)
  if (is.null(record_hash)) {
    stop(
      "the server returned no record_hash or manifest_hash for step ", step_id,
      ", so this job's map cannot link to it",
      call. = FALSE
    )
  }
  .record_job_step(job, step_id, record_hash, result[["signed_request"]])
  result
}

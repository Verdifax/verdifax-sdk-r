# The account owner publishes the account's records. A sealed record belongs
# to the account that made it, so only the account's owner key makes it
# public on its random link; the owner key withdraws it, and a Verdifax admin
# key can also withdraw it. Each decision is a run publication,
# verdifax.run-publication.v2, sealed with who decided (owner or
# verdifax_admin), placed in the account's signal feed as a run.published or
# run.unpublished event, and anchored on the public log. A v1 publication
# carries no decided_by and was the owner's. verdifax-verify --signals reads
# v1 since v0.24.0 and v2 since v0.26.0.

#' Make one of the account's records public on its random link.
#'
#' Calls `POST /account/runs/{id}/publish` with the account's owner key. The
#' record may have been made by any key of the account. The decision is
#' sealed as a run publication, anchored on the public log and placed in the
#' account's signal feed as a `run.published` event. Idempotent: a record
#' already public is answered as it is, with `publication` `NULL`. The
#' service's admin key cannot publish another key's record.
#'
#' @inheritParams verdifax_get_account
#' @param run_id The run's id, a positive whole number.
#'
#' @return Parsed API response list: `ok`, `run_id`, `public`,
#'   `public_bundle_url` while public and the run has a bundle, or
#'   `public_receipt_url` while public and the run stopped (R156),
#'   `verify_url` and `publication`, the
#'   sealed record (`format`, `action`, `decided_by`, `run_id`, `record_hash`, `job_id`,
#'   `step_id`, `changed_at`, `signal`, `publication_hash`, `anchor`) or
#'   `NULL` when the run was already in the asked state.
#' @export
verdifax_publish_run <- function(client, run_id) {
  .send(client, "POST", paste0("/account", .run_path(run_id, "/publish")))
}

#' Withdraw one of the account's records from its public link.
#'
#' Calls `POST /account/runs/{id}/unpublish` with the account's owner key.
#' Both public routes answer 404 for the record afterwards; its link is kept,
#' so a later [verdifax_publish_run()] restores it. Sealed and placed in the
#' feed as a `run.unpublished` event. Idempotent for a run that is not public.
#'
#' @inheritParams verdifax_publish_run
#'
#' @return The same list as [verdifax_publish_run()], with `public` `FALSE`.
#' @export
verdifax_unpublish_run <- function(client, run_id) {
  .send(client, "POST", paste0("/account", .run_path(run_id, "/unpublish")))
}

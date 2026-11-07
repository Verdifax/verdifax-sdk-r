# ----------------------------------------------------------------------------
# verdifax, canonical hash formulas
# ----------------------------------------------------------------------------
#
# The three formulas from the Verdifax orchestrator, so a caller can
# recompute a DSE dispatch hash, a DCAE closure hash or a CRES receipt
# hash without calling the server. They match the Python SDK's
# verdifax.section0 and pass its test vectors. Every hash is SHA-256 as
# 64 lowercase hex characters, over UTF-8 text.

.DSE_FORMULA_VERSION <- "dse.tcu.dispatch.v1"
.DCAE_PREIMAGE_VERSION <- "verdifax.dcae.v1"
.CRES_PREIMAGE_VERSION <- "verdifax.cres.v1"
.CRES_ENGINE_VERSION <- "verdifax-cres/1.0.0"

# The one SHA-256 helper in the package, also used for request signing. It
# needs only openssl, so these formulas work without the sodium package.
.sha256_hex <- function(preimage) {
  paste(as.character(openssl::sha256(.utf8_bytes(preimage))), collapse = "")
}

#' Check that a value is 64 lowercase hex characters.
#'
#' @param value The value to check.
#' @param field_name The name to use in the error message.
#'
#' @return `TRUE`, invisibly. Stops with an error otherwise.
#'
#' @export
verdifax_validate_hex64 <- function(value, field_name) {
  if (!is.character(value) || length(value) != 1 || is.na(value) ||
      !grepl("^[0-9a-f]{64}$", value)) {
    stop(field_name, " must be 64 lowercase hex characters", call. = FALSE)
  }
  invisible(TRUE)
}

#' Check that a value is a usable route identifier.
#'
#' @param value The value to check: non-empty printable ASCII of at most
#'   256 characters.
#'
#' @return `TRUE`, invisibly. Stops with an error otherwise.
#'
#' @export
verdifax_validate_route_id <- function(value) {
  if (!is.character(value) || length(value) != 1 || is.na(value) || !nzchar(value)) {
    stop("route_id is required", call. = FALSE)
  }
  if (nchar(value, type = "bytes") > 256) {
    stop("route_id is too long", call. = FALSE)
  }
  if (!grepl("^[\x20-\x7E]+$", value, useBytes = TRUE)) {
    stop("route_id contains a non-printable-ASCII character", call. = FALSE)
  }
  invisible(TRUE)
}

#' Compute a DSE dispatch hash. This formula joins its fields with a
#' period.
#'
#' @param envelope_id The envelope identifier.
#' @param sequence_id The per-envelope sequence identifier.
#' @param program_id 64-char lowercase hex program ID.
#' @param registry_record_hash 64-char lowercase hex record hash.
#'
#' @return The hash as 64 lowercase hex characters.
#'
#' @export
verdifax_dse_dispatch_hash <- function(envelope_id, sequence_id, program_id, registry_record_hash) {
  verdifax_validate_hex64(program_id, "program_id")
  verdifax_validate_hex64(registry_record_hash, "registry_record_hash")
  .sha256_hex(paste(
    .DSE_FORMULA_VERSION, envelope_id, sequence_id, program_id, registry_record_hash,
    sep = "."
  ))
}

#' Compute a DCAE closure hash. This formula joins its fields with a
#' pipe.
#'
#' @param manifest_hash 64-char lowercase hex manifest hash.
#' @param aer_hash 64-char lowercase hex AER hash.
#' @param envelope_id The envelope identifier.
#' @param zksp_binding_hash 64-char lowercase hex binding hash.
#' @param formal_verifier_status The status string.
#'
#' @return The hash as 64 lowercase hex characters.
#'
#' @export
verdifax_dcae_closure_hash <- function(manifest_hash,
                                       aer_hash,
                                       envelope_id,
                                       zksp_binding_hash,
                                       formal_verifier_status) {
  verdifax_validate_hex64(manifest_hash, "manifest_hash")
  verdifax_validate_hex64(aer_hash, "aer_hash")
  verdifax_validate_hex64(zksp_binding_hash, "zksp_binding_hash")
  .sha256_hex(paste(
    .DCAE_PREIMAGE_VERSION, manifest_hash, aer_hash, envelope_id,
    zksp_binding_hash, formal_verifier_status,
    sep = "|"
  ))
}

#' Compute a CRES receipt hash. This formula joins its fields with a
#' pipe.
#'
#' @param envelope_id The envelope identifier.
#' @param field_path The erased field's dotted path.
#' @param deletion_clock The RFC 3339 deletion time.
#' @param actor_id The identity that issued the deletion.
#' @param ciphertext_hash_at_shred 64-char lowercase hex ciphertext hash.
#' @param dsar_reference The originating request reference.
#' @param engine_version The engine version. Change it only to recompute
#'   a receipt from an earlier engine.
#'
#' @return The hash as 64 lowercase hex characters.
#'
#' @export
verdifax_cres_receipt_hash <- function(envelope_id,
                                       field_path,
                                       deletion_clock,
                                       actor_id,
                                       ciphertext_hash_at_shred,
                                       dsar_reference,
                                       engine_version = .CRES_ENGINE_VERSION) {
  verdifax_validate_hex64(ciphertext_hash_at_shred, "ciphertext_hash_at_shred")
  .sha256_hex(paste(
    .CRES_PREIMAGE_VERSION, envelope_id, field_path, deletion_clock, actor_id,
    ciphertext_hash_at_shred, dsar_reference, engine_version,
    sep = "|"
  ))
}

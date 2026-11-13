# ----------------------------------------------------------------------------
# verdifax, the signal feed, feed keys, webhooks and failure receipts
# ----------------------------------------------------------------------------
#
# The signal feed is every control signal Verdifax recorded for the account,
# in order: a run refused, halted or failed, a policy change, a sign-off, an
# approver key registered or revoked, a key created or revoked, an account
# change, a record deleted. A key change is verdifax.key-change.v2, which
# names who decided it (decided_by), or v1, the owner's. An account change
# also seals each key's own request key registered, replaced or cleared
# (request_key.registered, request_key.rotated, request_key.cleared), with
# the previous key's approval of a replacement or of its holder's clear.
# Each event is a CloudEvent that carries its place in the account's feed
# and the sealed entry it points to. A page that reaches the feed's end also
# carries the feed's head, verdifax.feed-head.v1: Verdifax's statement of
# the feed's highest event, anchored on the public log. The head is not an
# event. The feed cannot show a signal Verdifax never recorded.
#
# A feed key reads the feed and nothing else. The owner key reads the same
# feed on /account/signals, creates and revokes feed keys, and subscribes
# webhooks. A webhook delivery is a copy: the pull feed and the public log
# are the record.

.SIGNALS_PATH <- "/signals"
.FEED_KEYS_PATH <- "/account/feed-keys"
.WEBHOOKS_PATH <- "/account/webhooks"
.SIGNAL_FORM <- "verdifax.signal.v1"
.SIGNAL_KINDS <- c(
  "run.refused", "run.halted", "run.failed", "policy.changed", "signoff.recorded",
  "approver.registered", "approver.revoked", "key.created", "key.revoked",
  "run.published", "run.unpublished", "chain.gap", "run.sealed", "chain.interrupted",
  "account.changed", "run.deleted"
)
.SIGNAL_PAGE_MAX <- 500L
.SIGNAL_WAIT_MAX_SEC <- 25L
.DELIVERY_PAGE_MAX <- 500L
# A signals call may be held open for its whole wait, so its HTTP timeout is
# at least the wait plus this margin, whatever the client's own timeout.
.SIGNAL_TIMEOUT_MARGIN_SEC <- 30
# How long verdifax_follow_signals() pauses after an empty page read with
# wait = 0, so it never asks the server again at once.
.SIGNAL_IDLE_PAUSE_SEC <- 1
.SIGNAL_ACCOUNT_PATTERN <- "^account-[1-9][0-9]{0,18}$"
# The largest whole number a double holds exactly, so the place sent is the
# place read.
.SIGNAL_MAX_SEQUENCE <- 2^53 - 1
.WEBHOOK_SECRET_PREFIX <- "whsec_"
.WEBHOOK_TOLERANCE_SEC <- 300
.WEBHOOK_HEADERS <- c("webhook-id", "webhook-timestamp", "webhook-signature")


# ── Input checks ────────────────────────────────────────────────────────────

.is_whole <- function(value) {
  is.numeric(value) && length(value) == 1 && !is.na(value) && is.finite(value) &&
    value == floor(value)
}

.signal_after <- function(after) {
  if (!.is_whole(after) || after < 0 || after > .SIGNAL_MAX_SEQUENCE) {
    stop("after must be a whole number of 0 or more, the last sequence read", call. = FALSE)
  }
  as.vector(after)
}

.signal_limit <- function(limit, max = .SIGNAL_PAGE_MAX) {
  if (is.null(limit)) {
    return(NULL)
  }
  if (!.is_whole(limit) || limit < 1 || limit > max) {
    stop("limit must be a whole number from 1 to ", max, ", or NULL", call. = FALSE)
  }
  as.vector(limit)
}

.signal_wait <- function(wait) {
  if (!.is_whole(wait) || wait < 0 || wait > .SIGNAL_WAIT_MAX_SEC) {
    stop("wait must be a whole number of seconds from 0 to ", .SIGNAL_WAIT_MAX_SEC, call. = FALSE)
  }
  as.vector(wait)
}

.webhook_url <- function(url) {
  if (!is.character(url) || length(url) != 1 || is.na(url) ||
      !startsWith(url, "https://") || nchar(url) <= nchar("https://")) {
    stop("url must be a single string starting with https://", call. = FALSE)
  }
  as.vector(url)
}

# The kinds as sent, or NULL for every kind. A list is always sent as a JSON
# array, even with one kind.
.webhook_types <- function(types) {
  if (is.null(types) || (is.character(types) && length(types) == 0)) {
    return(NULL)
  }
  if (!is.character(types) || anyNA(types) || !all(types %in% .SIGNAL_KINDS)) {
    stop(
      "types must be signal kinds, each one of ", paste(.SIGNAL_KINDS, collapse = ", "),
      ", or NULL for every kind",
      call. = FALSE
    )
  }
  if (anyDuplicated(types) > 0) {
    stop("types names a kind twice", call. = FALSE)
  }
  as.list(as.vector(types))
}

# Any single string with no zero byte, so a kind the server adds later still
# hashes. The known kinds are checked only for webhook types.
.signal_kind <- function(kind) {
  if (!is.character(kind) || length(kind) != 1 || is.na(kind) ||
      any(.utf8_bytes(kind) == as.raw(0))) {
    stop("kind must be a single string with no zero byte, for example run.refused", call. = FALSE)
  }
  as.vector(kind)
}


# ── Requests ────────────────────────────────────────────────────────────────

# The GET of one page. The HTTP timeout covers the wait, and the client's
# retry policy applies as to every GET.
.signals_request <- function(client, after, limit, wait, as_owner) {
  base <- .signoff_base(as_owner)
  after <- .signal_after(after)
  limit <- .signal_limit(limit)
  wait <- .signal_wait(wait)
  timed <- client
  timed$timeout <- max(client$timeout %||% .DEFAULT_TIMEOUT_SEC, wait + .SIGNAL_TIMEOUT_MARGIN_SEC)
  .get(timed, paste0(base, .SIGNALS_PATH), .query(after = after, limit = limit, wait = wait))
}


# ── The feed ────────────────────────────────────────────────────────────────

#' Read one page of the account's signal feed.
#'
#' Calls `GET /signals` with a feed key, or with `as_owner = TRUE` the owner
#' key's `GET /account/signals`. The feed is every control signal Verdifax
#' recorded for the account, in order, each with its sealed entry. It cannot
#' show a signal Verdifax never recorded. Bad input is refused before
#' anything is sent.
#'
#' The HTTP timeout of this call is at least `wait` plus 30 seconds, whatever
#' the client's own timeout, because the server may hold the request open for
#' the whole wait. A failed read is retried with the client's retry policy,
#' as every GET is.
#'
#' @param client A client handle from `verdifax_client()`, holding a feed key
#'   of the account, or its owner key with `as_owner = TRUE`.
#' @param after The last sequence read, a whole number of 0 or more. The page
#'   starts at the next event.
#' @param limit Optional page size, a whole number from 1 to 500. `NULL`
#'   leaves the server's default of 100.
#' @param wait Seconds the server may wait for a first event when there is
#'   none yet, a whole number from 0 to 25.
#' @param as_owner `TRUE` to use the owner key's `/account` route.
#'
#' @return Parsed API response list with `events`, a list of CloudEvents,
#'   oldest first; `next_after`, the `after` to read the next page with; and
#'   `newest`, the account's newest sequence. Each event holds `specversion`,
#'   `id` (for example `"account-7/12"`), `source`, `type` (for example
#'   `"com.verdifax.run.refused"`), `time`, `datacontenttype` and `data`. The
#'   `data` holds `form`, `kind`, `account`, `sequence`,
#'   `previous_signal_hash`, `event_hash`, the sealed `entry`, and where they
#'   apply `run_id`, `api_key_id` and `reason`. For an event whose entry is
#'   a record that was deleted, for example a refused run's receipt event,
#'   `entry` is `NULL` and `deleted` holds that record's sealed tombstone,
#'   `verdifax.run-deletion.v1`, as `verdifax_delete_run()` returns it in
#'   `run_deletion`, `log_entries` and `job_links` included;
#'   `verdifax-verify --signals` reads it since v0.33.0. A `run.sealed` event keeps its own entry, since
#'   it is its own sealed record.
#'
#'   An `account.changed` entry is a `verdifax.account-change.v1` record
#'   with `format`, `action`, `decided_by`, `key_id`, `value`, `changed_at`,
#'   `signal`, `account_change_hash` and `anchor`, and where it applies
#'   `owner_signature` or `request_key_approval`. A key's holder registering
#'   its first request key is `request_key.registered`, with the new public
#'   key (base64) as `value` and `decided_by` `"owner"`. Replacing it is
#'   `request_key.rotated`, with the new public key as `value` and
#'   `request_key_approval`, the previous key's `public_key`, `signature`,
#'   `signed_at` and `nonce`, signed over the same request-key change
#'   `verdifax_rotate_request_key()` signs. The holder's own clear is
#'   `request_key.cleared` with an empty `value`, decided by `"owner"` and
#'   approved the same way over the empty key; a clear Verdifax decides
#'   carries no approval.
#'
#'   When the page reaches the feed's end it also holds `head`, Verdifax's
#'   statement of the feed's highest event: `format`
#'   (`"verdifax.feed-head.v1"`), `account`, `sequence`, `head_hash` (that
#'   event's hash), `stated_at`, `head_statement_hash` and `anchor`, its
#'   entry on the public log. The head is not an event. `verdifax-verify
#'   --signals` checks a saved feed against it, so a feed cut short before
#'   a later event fails.
#'
#' @export
verdifax_get_signals <- function(client, after = 0, limit = NULL, wait = 0, as_owner = FALSE) {
  .perform(.signals_request(client, after, limit, wait, as_owner))
}

# The error raised when following stops, holding the last sequence handled
# and that event's event_hash, so the caller can resume there with both, and
# the feed head kept so far.
.follow_error <- function(after, message, parent = NULL, head = NULL, after_event_hash = NULL) {
  place <- format(after, scientific = FALSE, trim = TRUE)
  structure(
    class = c("verdifax_follow_error", "error", "condition"),
    list(
      message = paste0(
        "following the signal feed stopped after sequence ", place, ": ", message,
        "; resume with after = ", place
      ),
      call = NULL,
      after = after,
      parent = parent,
      head = head,
      after_event_hash = after_event_hash
    )
  )
}

# Whether `read`, the head of a page whose events were all handled, is one
# to keep over `kept`: it states the feed through the last event handled,
# its sequence the page's `next_after` and its head_hash that event's
# event_hash, `handled_hash`; it is not the head statement already kept (the
# same head_statement_hash, as served again on an idle read); and it states
# no lower sequence. A fresh statement for the same sequence, which the
# server makes once its 5-minute reuse ends, replaces the one kept. Before an
# event is handled `handled_hash` is the caller's after_event_hash, and with
# none it is NULL and no head is kept.
.newer_head <- function(kept, read, next_after, handled_hash) {
  if (is.null(read) || !.is_whole(read[["sequence"]]) || read[["sequence"]] != next_after ||
      !is.character(handled_hash) || length(handled_hash) != 1 || !nzchar(handled_hash) ||
      !identical(read[["head_hash"]], handled_hash)) {
    return(FALSE)
  }
  is.null(kept) || (read[["sequence"]] >= kept[["sequence"]] &&
    !identical(read[["head_statement_hash"]], kept[["head_statement_hash"]]))
}

# An event's place in the feed, or NULL when it holds none.
.event_sequence <- function(event) {
  sequence <- if (is.list(event) && is.list(event[["data"]])) event[["data"]][["sequence"]]
  if (.is_whole(sequence)) sequence else NULL
}

# A page read from `place` must move on from it without a gap the server did
# not account for: every event carries its sequence, in rising order, after
# `place`, and next_after is the last event's sequence, or `place` itself
# when the page is empty. A head, when the page holds one, is an object.
# Anything else stops following before any event of the page is handled, so
# no event is skipped. `head` is the head kept before this page, and
# `handled_hash` the event_hash of the last event handled, for the error.
.check_signals_page <- function(page, place, head = NULL, handled_hash = NULL) {
  events <- if (is.list(page)) page[["events"]]
  next_after <- if (is.list(page)) page[["next_after"]]
  if (!is.list(events) || !.is_whole(next_after)) {
    stop(.follow_error(place, "the server's page has no events list or no next_after", head = head,
                       after_event_hash = handled_hash))
  }
  sequences <- vapply(events, function(event) .event_sequence(event) %||% NA_real_, numeric(1))
  in_order <- !anyNA(sequences) && all(diff(c(place, sequences)) > 0)
  last <- if (length(sequences) == 0) place else sequences[[length(sequences)]]
  if (!in_order || next_after != last) {
    stop(.follow_error(
      place,
      "the server's page holds an event out of order or without data$sequence, or a next_after that is not its last event",
      head = head, after_event_hash = handled_hash
    ))
  }
  read <- page[["head"]]
  if (!is.null(read) && (!is.list(read) || is.null(names(read)))) {
    stop(.follow_error(place, "the server's page holds a head that is not an object", head = head,
                       after_event_hash = handled_hash))
  }
  invisible(TRUE)
}

#' Follow the account's signal feed, calling a function on each event.
#'
#' Reads the feed page after page from `after`, with `verdifax_get_signals()`,
#' and calls `handler(event)` on each event in order. Each page is read from
#' the `next_after` of the one before, so no event is skipped. When a page is
#' empty the next read asks the server to wait up to `wait` seconds for an
#' event; with `wait = 0` it pauses one second first. A failed read is
#' retried with the client's retry policy, as every GET is.
#'
#' Following stops when `handler` returns `FALSE`. Any other return value,
#' `NULL` included, goes on. It never loses its place: when a read fails, the
#' server's page is out of order, or `handler` raises an error, it stops with
#' an error of class `verdifax_follow_error` whose `after` is the last
#' sequence handled, whose `after_event_hash` is that event's `event_hash`
#' (the one given when no event was handled, or `NULL` when none was given)
#' and whose `parent` is the error that stopped it. Calling again with that
#' `after` and `after_event_hash` reads on from there, beginning with the
#' event that was not handled, and keeps a head for event `after`.
#'
#' A page that reaches the feed's end holds the feed's `head`, Verdifax's
#' anchored statement of the feed's highest event (see
#' `verdifax_get_signals()`). The head is never passed to `handler` as an
#' event. Following keeps a page's head only once `handler` has handled
#' every event on that page without stopping, and only when the head's
#' `sequence` is the page's `next_after` and its `head_hash` is the
#' `event_hash` of the last event handled, so a kept head always states the
#' feed through the events the caller handled. Before `handler` handles an
#' event, the last event handled is event `after`, whose hash the caller may
#' give as `after_event_hash`: a follower resuming at the feed's end then
#' keeps the head it is served. Without it, no head is kept until an event
#' is handled. The
#' head statement already kept (the same `head_statement_hash`), served
#' again on an idle read, is not kept again, and nor is one stating a lower
#' sequence; a fresh statement for the same sequence, made once the server's
#' 5-minute reuse ends, replaces it. The kept head is passed to `on_head`
#' when it is kept, after its page's events; it is the `head` attribute of
#' the value returned and the `head` of a `verdifax_follow_error`. Each is
#' `NULL` until a head is kept.
#'
#' @inheritParams verdifax_get_signals
#' @param handler A function of one argument, the event, as a CloudEvent list
#'   from `verdifax_get_signals()`.
#' @param wait Seconds the server may wait for an event when there is none
#'   yet, a whole number from 0 to 25. Defaults to 25.
#' @param on_head Optional function of one argument, called with each feed
#'   head as it is kept. Its return value is ignored. An error it raises
#'   stops following as an error of `handler` does.
#' @param after_event_hash Optional `event_hash` of event `after`, 64
#'   lowercase hex characters, as you saved it with that event's sequence.
#'   Anything else is refused before any request. `NULL` keeps no head until
#'   `handler` has handled an event.
#'
#' @return The last sequence handled, invisibly, once `handler` returns
#'   `FALSE`, with the newest feed head kept as its `head` attribute when one
#'   was kept.
#'
#' @export
verdifax_follow_signals <- function(client, handler, after = 0, wait = 25, as_owner = FALSE,
                                    on_head = NULL, after_event_hash = NULL) {
  if (!is.function(handler)) {
    stop("handler must be a function of one event", call. = FALSE)
  }
  if (!is.null(on_head) && !is.function(on_head)) {
    stop("on_head must be a function of one feed head, or NULL", call. = FALSE)
  }
  if (!is.null(after_event_hash)) {
    verdifax_validate_hex64(after_event_hash, "after_event_hash")
  }
  .signoff_base(as_owner)
  place <- .signal_after(after)
  wait <- .signal_wait(wait)
  head <- NULL
  # The event_hash of the last event handled: event `after`, as the caller
  # gave it, until the first event of this call is handled.
  handled_hash <- if (is.null(after_event_hash)) NULL else as.vector(after_event_hash)
  stopped <- function(e) stop(.follow_error(place, conditionMessage(e), e, head, handled_hash))
  repeat {
    page <- tryCatch(.perform(.signals_request(client, place, NULL, wait, as_owner)), error = stopped)
    .check_signals_page(page, place, head, handled_hash)
    events <- page[["events"]]
    for (event in events) {
      sequence <- .event_sequence(event)
      result <- tryCatch(handler(event), error = stopped)
      place <- sequence
      handled_hash <- event[["data"]][["event_hash"]]
      if (isFALSE(result)) {
        attr(place, "head") <- head
        return(invisible(place))
      }
    }
    if (.newer_head(head, page[["head"]], page[["next_after"]], handled_hash)) {
      head <- page[["head"]]
      if (!is.null(on_head)) {
        tryCatch(on_head(head), error = stopped)
      }
    }
    if (length(events) == 0 && wait == 0) {
      Sys.sleep(.SIGNAL_IDLE_PAUSE_SEC)
    }
  }
}


# ── Feed keys ───────────────────────────────────────────────────────────────

#' Create a feed key in the owner key's account.
#'
#' Calls `POST /account/feed-keys`. A feed key reads the account's signal
#' feed, with `verdifax_get_signals()` and `verdifax_follow_signals()`, and
#' nothing else. Creating one is itself a signal on the feed.
#'
#' @inheritParams verdifax_get_account
#' @param name The key's name, a single non-empty string.
#' @param expires_at Optional expiry, an RFC 3339 time or a `YYYY-MM-DD`
#'   date.
#'
#' @return Parsed API response list with `ok`, `id`, `name`, `secret`,
#'   `hint`, `tier` and `account_id`. It holds the secret once: pass it as
#'   `api_key` to `verdifax_client()` to read the feed.
#'
#' @export
verdifax_create_feed_key <- function(client, name, expires_at = NULL) {
  body <- list(name = .account_string(name, "name", required = TRUE))
  body$expires_at <- .account_string(expires_at, "expires_at")
  .send(client, "POST", .FEED_KEYS_PATH, body)
}

#' Revoke one of the account's feed keys.
#'
#' Calls `DELETE /account/feed-keys/{id}`. An id that is not a feed key of
#' the account answers HTTP 404, and the call stops with the server's
#' message. Revoking one is itself a signal on the feed.
#'
#' @inheritParams verdifax_get_account
#' @param id The feed key's `id`, a positive whole number.
#'
#' @return Parsed API response list with `ok`, `id` and `revoked`.
#'
#' @export
verdifax_revoke_feed_key <- function(client, id) {
  .send(client, "DELETE", paste0(.FEED_KEYS_PATH, "/", .require_id(id, "id")))
}


# ── Webhooks ────────────────────────────────────────────────────────────────

#' Subscribe a webhook to the account's signals.
#'
#' Calls `POST /account/webhooks`. Verdifax posts each new event of the
#' chosen kinds to `url`, signed under the Standard Webhooks scheme; check
#' each delivery with `verdifax_verify_webhook()`. A delivery is a copy: the
#' pull feed and the public log are the record. The server checks the
#' address too, so the check here is only the first one. An account holds
#' at most ten webhooks; one more answers HTTP 409.
#'
#' @inheritParams verdifax_get_account
#' @param url The address to post to, a single string starting with
#'   `https://`.
#' @param types Optional character vector of signal kinds, each one of
#'   `run.refused`, `run.halted`, `run.failed`, `policy.changed`,
#'   `signoff.recorded`, `approver.registered`, `approver.revoked`,
#'   `key.created`, `key.revoked`, `run.published`, `run.unpublished`,
#'   `chain.gap`, `run.sealed`, `chain.interrupted`, `account.changed` and
#'   `run.deleted`, with no repeats. `NULL` takes every kind.
#'
#' @return Parsed API response list with `ok`, `id`, `url`, `types`,
#'   `created_at`, `secret` (`whsec_` and base64) and `hint`. It holds the
#'   secret once: store it to check deliveries.
#'
#' @export
verdifax_create_webhook <- function(client, url, types = NULL) {
  body <- list(url = .webhook_url(url))
  body$types <- .webhook_types(types)
  .send(client, "POST", .WEBHOOKS_PATH, body)
}

#' List the account's webhooks, without their secrets.
#'
#' Calls `GET /account/webhooks`.
#'
#' @inheritParams verdifax_get_account
#'
#' @return Parsed API response list with `ok` and `webhooks`. Each holds
#'   `id`, `url`, `types` and `created_at`.
#'
#' @export
verdifax_list_webhooks <- function(client) {
  .perform(.get(client, .WEBHOOKS_PATH))
}

#' Delete one of the account's webhooks.
#'
#' Calls `DELETE /account/webhooks/{id}`. Nothing more is posted to it. The
#' feed is unchanged.
#'
#' @inheritParams verdifax_get_account
#' @param id The webhook's `id`, a positive whole number.
#'
#' @return Parsed API response list with `ok`, `id` and `deleted`.
#'
#' @export
verdifax_delete_webhook <- function(client, id) {
  .send(client, "DELETE", paste0(.WEBHOOKS_PATH, "/", .require_id(id, "id")))
}

#' The delivery log of one of the account's webhooks.
#'
#' Calls `GET /account/webhooks/{id}/deliveries`.
#'
#' @inheritParams verdifax_get_account
#' @param id The webhook's `id`, a positive whole number.
#' @param limit Optional number of deliveries, a whole number from 1 to 500.
#'   `NULL` leaves the server's default of 50.
#'
#' @return Parsed API response list with `ok`, `webhook_id` and
#'   `deliveries`. Each holds `sequence`, `status`, `attempts`,
#'   `last_status_code`, `last_error`, `created_at` and, where they apply,
#'   `delivered_at` and `next_attempt_at`.
#'
#' @export
verdifax_list_webhook_deliveries <- function(client, id, limit = NULL) {
  path <- paste0(.WEBHOOKS_PATH, "/", .require_id(id, "id"), "/deliveries")
  limit <- .signal_limit(limit, .DELIVERY_PAGE_MAX)
  .perform(.get(client, path, .query(limit = limit)))
}


# ── Checking a webhook ──────────────────────────────────────────────────────

.webhook_error <- function(message) {
  structure(
    class = c("verdifax_webhook_error", "error", "condition"),
    list(message = paste0("webhook check failed: ", message), call = NULL)
  )
}

# One header, found whatever the case of its name.
.webhook_header <- function(headers, name) {
  found <- which(tolower(names(headers)) == name)
  if (length(found) == 0) {
    stop(.webhook_error(paste0("the ", name, " header is missing")))
  }
  if (length(found) > 1) {
    stop(.webhook_error(paste0("the ", name, " header is given more than once")))
  }
  value <- headers[[found]]
  if (!is.character(value) || length(value) != 1 || is.na(value) || !nzchar(value)) {
    stop(.webhook_error(paste0("the ", name, " header must be a single non-empty string")))
  }
  as.vector(value)
}

# Strict base64, decoded, or NULL.
.base64_strict <- function(value) {
  if (!grepl("^[A-Za-z0-9+/]+={0,2}$", value) || nchar(value) %% 4 != 0) {
    return(NULL)
  }
  raw <- tryCatch(jsonlite::base64_dec(value), error = function(e) NULL)
  if (length(raw) == 0) NULL else raw
}

# The secret's bytes. The secret itself never appears in a message.
.webhook_secret <- function(secret) {
  if (!is.character(secret) || length(secret) != 1 || is.na(secret) ||
      !startsWith(secret, .WEBHOOK_SECRET_PREFIX)) {
    stop(.webhook_error("the secret must be a single string starting with whsec_"))
  }
  key <- .base64_strict(substring(secret, nchar(.WEBHOOK_SECRET_PREFIX) + 1))
  if (is.null(key)) {
    stop(.webhook_error("the secret after whsec_ must be base64"))
  }
  key
}

.webhook_body <- function(body) {
  if (is.raw(body)) {
    return(body)
  }
  if (is.character(body) && length(body) == 1 && !is.na(body)) {
    return(charToRaw(enc2utf8(body)))
  }
  stop(.webhook_error("the body must be the raw bytes received, as a raw vector or a single string"))
}

# Seconds since 1970 of `now`, a POSIXct time or a number.
.webhook_now <- function(now) {
  if ((!inherits(now, "POSIXct") && !is.numeric(now)) || length(now) != 1 ||
      is.na(now) || !is.finite(as.numeric(now))) {
    stop(.webhook_error("now must be a single POSIXct time or a number of seconds since 1970"))
  }
  as.numeric(now)
}

# Equal raw vectors, comparing every byte of `expected` without an early
# exit, so the time taken does not show how many bytes matched.
.constant_time_equal <- function(expected, candidate) {
  difference <- if (length(candidate) == length(expected)) 0L else 1L
  padded <- c(candidate, raw(length(expected)))[seq_along(expected)]
  for (i in seq_along(expected)) {
    difference <- bitwOr(difference, bitwXor(as.integer(expected[[i]]), as.integer(padded[[i]])))
  }
  difference == 0L
}

#' Check a webhook delivery and return its event.
#'
#' Checks a delivery under the Standard Webhooks scheme, without sending
#' anything. The signed content is the `webhook-id` header, a dot, the
#' `webhook-timestamp` header, a dot and the raw body bytes, and its
#' HMAC-SHA256 under the secret's bytes must match one of the `v1,` entries
#' in the `webhook-signature` header. Each signature is compared in constant
#' time. A timestamp more than `tolerance_seconds` from `now`, in either
#' direction, is refused. Header names are matched whatever their case. The
#' body must be a JSON object whose top-level `id` is a string equal to the
#' `webhook-id` header.
#'
#' A delivery is a copy: the pull feed and the public log are the record.
#'
#' @param headers The request's headers, a named list or named character
#'   vector.
#' @param body The raw body bytes as received, a raw vector, or a single
#'   string holding exactly those bytes. Pass the body before any JSON
#'   parsing: parsed and written again, it no longer matches.
#' @param secret The webhook's secret from `verdifax_create_webhook()`,
#'   `whsec_` and base64. It is never shown in a message.
#' @param tolerance_seconds How far the timestamp may be from `now`, in
#'   seconds. Defaults to 300.
#' @param now The time to check against, a POSIXct time or seconds since
#'   1970. Defaults to `Sys.time()`.
#'
#' @return The delivered CloudEvent, parsed from the body. Stops with an
#'   error of class `verdifax_webhook_error` that says which check failed
#'   otherwise.
#'
#' @export
verdifax_verify_webhook <- function(headers, body, secret, tolerance_seconds = .WEBHOOK_TOLERANCE_SEC,
                                    now = Sys.time()) {
  key <- .webhook_secret(secret)
  bytes <- .webhook_body(body)
  if (!is.numeric(tolerance_seconds) || length(tolerance_seconds) != 1 ||
      is.na(tolerance_seconds) || !is.finite(tolerance_seconds) || tolerance_seconds < 0) {
    stop(.webhook_error("tolerance_seconds must be a number of 0 or more"))
  }
  now <- .webhook_now(now)
  if (is.null(names(headers)) || !(is.list(headers) || is.character(headers))) {
    stop(.webhook_error("headers must be a named list or named character vector"))
  }
  id <- .webhook_header(headers, "webhook-id")
  timestamp <- .webhook_header(headers, "webhook-timestamp")
  signature <- .webhook_header(headers, "webhook-signature")
  if (!grepl("^[0-9]{1,15}$", timestamp)) {
    stop(.webhook_error("the webhook-timestamp header must be whole seconds since 1970"))
  }
  if (abs(now - as.numeric(timestamp)) > tolerance_seconds) {
    stop(.webhook_error(paste0(
      "the webhook-timestamp is more than ", tolerance_seconds, " seconds from now"
    )))
  }
  entries <- strsplit(trimws(signature), " +")[[1]]
  signed <- entries[startsWith(entries, "v1,")]
  if (length(signed) == 0) {
    stop(.webhook_error("the webhook-signature header holds no v1 signature"))
  }
  expected <- as.raw(openssl::sha256(c(charToRaw(paste0(id, ".", timestamp, ".")), bytes), key = key))
  matched <- FALSE
  for (entry in signed) {
    candidate <- .base64_strict(substring(entry, 4)) %||% raw(0)
    matched <- .constant_time_equal(expected, candidate) || matched
  }
  if (!matched) {
    stop(.webhook_error("no v1 signature in webhook-signature matches the body under this secret"))
  }
  event <- tryCatch(
    jsonlite::fromJSON(rawToChar(bytes), simplifyVector = FALSE),
    error = function(e) NULL
  )
  if (!is.list(event) || is.null(names(event))) {
    stop(.webhook_error("the signed body is not a JSON CloudEvent"))
  }
  # The signature covers webhook-id and the body separately, so a body whose
  # own id differs from the header is refused here. Every top-level id is
  # checked, so a repeated key cannot hide one.
  ids <- event[names(event) == "id"]
  id_matches <- length(ids) > 0 && all(vapply(ids, function(body_id) {
    is.character(body_id) && length(body_id) == 1 && !is.na(body_id) && body_id == id
  }, logical(1)))
  if (!id_matches) {
    stop(.webhook_error("the event id in the body does not match webhook-id"))
  }
  event
}

#' The hash of one signal event.
#'
#' Recomputes an event's `event_hash` without calling the server: the hex
#' SHA-256 of `verdifax.signal.v1`, the kind, the hash of the event's sealed
#' entry, the account, the decimal sequence and the previous event's hash,
#' as UTF-8, joined by single zero bytes. The next event in the feed names
#' it as its `previous_signal_hash`, so a saved feed can be checked link by
#' link; `verdifax-verify --signals` checks a saved feed.
#'
#' @param kind The event's kind, for example `"run.refused"`. Any single
#'   string is accepted, so a kind added later still hashes.
#' @param entry_hash 64-char lowercase hex hash of the event's sealed entry.
#' @param account The account, for example `"account-7"`.
#' @param sequence The event's sequence, a positive whole number.
#' @param previous_signal_hash 64-char lowercase hex hash of the account's
#'   previous event, or 64 zeros for the first.
#'
#' @return The hash as 64 lowercase hex characters.
#'
#' @export
verdifax_signal_event_hash <- function(kind, entry_hash, account, sequence, previous_signal_hash) {
  kind <- .signal_kind(kind)
  verdifax_validate_hex64(entry_hash, "entry_hash")
  if (!is.character(account) || length(account) != 1 || is.na(account) ||
      !grepl(.SIGNAL_ACCOUNT_PATTERN, account)) {
    stop("account must be an account, for example account-7", call. = FALSE)
  }
  if (!.is_whole(sequence) || sequence < 1 || sequence > .SIGNAL_MAX_SEQUENCE) {
    stop("sequence must be a positive whole number", call. = FALSE)
  }
  verdifax_validate_hex64(previous_signal_hash, "previous_signal_hash")
  preimage <- .join_with_zero(list(
    .SIGNAL_FORM, kind, entry_hash, account,
    format(sequence, scientific = FALSE, trim = TRUE), previous_signal_hash
  ))
  paste(as.character(openssl::sha256(preimage)), collapse = "")
}


# ── Failure receipts ────────────────────────────────────────────────────────

#' The failure receipt of a run that failed.
#'
#' Calls `GET /runs/{id}/failure-receipt` with a member key. A failed run
#' from before failure receipts answers HTTP 404, and the call stops with the
#' server's message. Save the text with `writeLines(text, path, sep = "")`.
#' It is not parsed, so what you save is what the server sent.
#'
#' @inheritParams verdifax_verify_run
#' @param run_id The run's id, a positive whole number.
#'
#' @return The exact JSON text the server sent, as a single string: `ok`,
#'   `run_id`, `failure_receipt` and, where they apply, `receipt_anchor`
#'   and `receipt_context`. Read it with `jsonlite::fromJSON()`.
#'
#' @export
verdifax_get_failure_receipt <- function(client, run_id) {
  .get_body_text(client, paste0("/runs/", .require_id(run_id, "run_id"), "/failure-receipt"))
}

# ── Sign-offs a rule requires ───────────────────────────────────────────────

#' List the runs still waiting for a sign-off their rule requires.
#'
#' Round 58, B7. A policy rule can require a person's sign-off on the
#' results it allows; each such run's `run.sealed` event says
#' `signoff_required`. This returns, in feed order, those runs on whose
#' record no approval is in force. The decision in force is read as
#' `verdifax-verify` reads it: the last job sign-off on the run governs when
#' there is one, and otherwise the last record sign-off; a receipt sign-off
#' does not name a record (round 59, N15 and N19). A run whose record was
#' deleted, by a `run.deleted` event for its `run_id` at any place in the
#' events given, is left out, since there is no record left to sign off. A
#' `run.sealed` event is its own sealed record, so the feed keeps its entry
#' when the run's record is deleted. A `run.sealed` or `run.deleted` event
#' whose entry names no run, a positive whole number, stops with an error;
#' every other kind is passed over. The shared vector
#' `sdk-pending-signoffs-vector.json` holds the four SDKs to this rule.
#' Pass the account's feed from its start, or a page that includes each
#' run's sign-offs and deletion, so a sign-off or deletion recorded later is
#' seen.
#'
#' @param events A list of feed events, as `verdifax_get_signals()` returns
#'   in its `events`.
#'
#' @return An integer vector of run ids.
#'
#' @export
verdifax_pending_signoffs <- function(events) {
  order <- integer(0)
  latest_job <- list()
  latest_record <- list()
  deleted <- numeric(0)
  for (e in events) {
    data <- e$data
    entry <- data$entry
    if (identical(data$kind, "run.sealed")) {
      run <- entry$run_id
      if (!.is_whole(run) || run < 1) {
        stop("verdifax: the run.sealed entry of event ", e$id, " names no run", call. = FALSE)
      }
      if (isTRUE(entry$signoff_required) && !(run %in% order)) {
        order <- c(order, as.integer(run))
      }
    } else if (identical(data$kind, "run.deleted")) {
      run <- entry$run_id
      if (!.is_whole(run) || run < 1) {
        stop("verdifax: the run.deleted entry of event ", e$id, " names no run", call. = FALSE)
      }
      deleted <- c(deleted, run)
    } else if (identical(data$kind, "signoff.recorded")) {
      target <- entry$target
      if (is.numeric(target$run_id)) {
        if (identical(target$kind, "job")) {
          latest_job[[as.character(target$run_id)]] <- entry$decision
        } else if (identical(target$kind, "record")) {
          latest_record[[as.character(target$run_id)]] <- entry$decision
        }
      }
    }
  }
  in_force <- function(run) {
    key <- as.character(run)
    if (!is.null(latest_job[[key]])) latest_job[[key]] else latest_record[[key]]
  }
  keep <- vapply(order, function(run) {
    !(run %in% deleted) && !identical(in_force(run), "approve")
  }, logical(1))
  order[keep]
}

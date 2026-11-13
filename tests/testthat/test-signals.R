# The signal feed, feed keys, webhooks, failure receipts and the webhook
# check. Requests are captured by a mock, so nothing reaches the network.

.vector <- jsonlite::fromJSON(testthat::test_path("sdk-signature-vector.json"))
.kinds <- c(
  "run.refused", "run.halted", "run.failed", "policy.changed", "signoff.recorded",
  "approver.registered", "approver.revoked", "key.created", "key.revoked"
)

feed_client <- function(...) {
  verdifax_client(base_url = "http://mock.invalid", api_key = "feed", ...)
}

owner_client <- function() {
  verdifax_client(base_url = "http://mock.invalid", api_key = "owner")
}

member_client <- function() {
  verdifax_client(base_url = "http://mock.invalid", api_key = "member")
}

json_response <- function(text, status = 200) {
  httr2::response(
    status_code = status,
    headers = "Content-Type: application/json",
    body = charToRaw(enc2utf8(text))
  )
}

to_json <- function(value) {
  as.character(jsonlite::toJSON(value, auto_unbox = TRUE, digits = 22, null = "null"))
}

# An event's hash, derived from its sequence, as the shared feed-head vector
# says: the SHA-256 of "e" and the sequence.
event_hash_of <- function(sequence) as.character(openssl::sha256(paste0("e", sequence)))

# One CloudEvent of the feed.
cloud_event <- function(sequence, kind = "run.refused") {
  list(
    specversion = "1.0",
    id = paste0("account-7/", sequence),
    source = "https://api.verdifax.com/accounts/account-7",
    type = paste0("com.verdifax.", kind),
    time = "2026-11-07T12:00:00Z",
    datacontenttype = "application/json",
    data = list(
      form = "verdifax.signal.v1", kind = kind, account = "account-7", sequence = sequence,
      previous_signal_hash = strrep("e", 64), event_hash = event_hash_of(sequence), run_id = 42L,
      entry = list(hash = strrep("a", 64))
    )
  )
}

signals_page <- function(sequences, next_after, newest = 9L) {
  json_response(to_json(list(
    events = lapply(sequences, cloud_event), next_after = next_after, newest = newest
  )))
}

.feed_key_reply <- paste0(
  "{\"ok\":true,\"id\":12,\"name\":\"siem\",\"secret\":\"vfx_feed\",",
  "\"hint\":\"Store this secret now\",\"tier\":\"pilot\",\"account_id\":\"account-7\"}"
)
.webhook_reply <- paste0(
  "{\"ok\":true,\"id\":4,\"url\":\"https://hooks.example.com/verdifax\",",
  "\"types\":[\"run.refused\",\"run.halted\"],\"created_at\":\"2026-11-07T12:00:00Z\",",
  "\"secret\":\"whsec_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\",\"hint\":\"Store this secret now\"}"
)
.webhooks_reply <- paste0(
  "{\"ok\":true,\"webhooks\":[{\"id\":4,\"url\":\"https://hooks.example.com/verdifax\",",
  "\"types\":[],\"created_at\":\"2026-11-07T12:00:00Z\"}]}"
)
.deliveries_reply <- paste0(
  "{\"ok\":true,\"webhook_id\":4,\"deliveries\":[{\"sequence\":12,\"status\":\"delivered\",",
  "\"attempts\":1,\"last_status_code\":200,\"last_error\":\"\",\"created_at\":\"2026-11-07T12:00:00Z\",",
  "\"delivered_at\":\"2026-11-07T12:00:01Z\"}]}"
)

# Answers like the server: each route by its method and path.
signals_server <- function(req) {
  method <- httr2::req_get_method(req)
  path <- httr2::url_parse(httr2::req_get_url(req))$path
  route <- paste(method, path)
  if (route %in% c("GET /signals", "GET /account/signals")) {
    return(signals_page(list(1L, 2L), 2L))
  }
  if (route == "POST /account/feed-keys") {
    return(json_response(.feed_key_reply, 201))
  }
  if (method == "DELETE" && grepl("^/account/feed-keys/[0-9]+$", path)) {
    return(json_response(sprintf("{\"ok\":true,\"id\":%s,\"revoked\":true}", sub(".*/", "", path))))
  }
  if (route == "POST /account/webhooks") {
    return(json_response(.webhook_reply, 201))
  }
  if (route == "GET /account/webhooks") {
    return(json_response(.webhooks_reply))
  }
  if (method == "DELETE" && grepl("^/account/webhooks/[0-9]+$", path)) {
    return(json_response(sprintf("{\"ok\":true,\"id\":%s,\"deleted\":true}", sub(".*/", "", path))))
  }
  if (method == "GET" && grepl("^/account/webhooks/[0-9]+/deliveries$", path)) {
    return(json_response(.deliveries_reply))
  }
  json_response("{\"ok\":false,\"error\":\"not found\"}", 404)
}

# Runs `code` and returns what was sent: the method, path, query, key,
# timeout and the JSON text the request puts on the wire, written with the
# options req_body_json() uses.
capture <- function(code, respond = signals_server) {
  sent <- list()
  mock <- function(req) {
    body <- httr2::req_get_body(req)
    json <- if (is.null(body)) NULL else
      jsonlite::toJSON(body, auto_unbox = TRUE, digits = 22, null = "null")
    url <- httr2::url_parse(httr2::req_get_url(req))
    sent[[length(sent) + 1]] <<- list(
      method = httr2::req_get_method(req),
      path = url$path,
      query = url$query,
      key = httr2::req_get_headers(req, "reveal")[["X-Verdifax-Key"]],
      timeout = req$options$timeout_ms / 1000,
      retries = req$policies$retry_max_tries,
      json = if (is.null(json)) NULL else as.character(json),
      body = if (is.null(json)) NULL else jsonlite::fromJSON(json, simplifyVector = FALSE)
    )
    respond(req)
  }
  httr2::with_mocked_responses(mock, code)
  sent
}

parsed <- function(text) jsonlite::fromJSON(text, simplifyVector = FALSE)

zero_joined <- function(fields) {
  Reduce(function(a, b) c(a, as.raw(0), b), lapply(fields, function(text) charToRaw(enc2utf8(text))))
}


# ── The feed ────────────────────────────────────────────────────────────────

test_that("get_signals reads GET /signals with a feed key and the default query", {
  sent <- capture(result <- verdifax_get_signals(feed_client()))
  expect_length(sent, 1)
  expect_equal(sent[[1]]$method, "GET")
  expect_equal(sent[[1]]$path, "/signals")
  expect_equal(sent[[1]]$query, list(after = "0", wait = "0"))
  expect_equal(sent[[1]]$key, "feed")
  expect_null(sent[[1]]$body)
  expect_length(result$events, 2)
  expect_equal(result$next_after, 2L)
  expect_equal(result$newest, 9L)
  expect_equal(result$events[[1]]$type, "com.verdifax.run.refused")
  expect_equal(result$events[[2]]$data$sequence, 2L)
})

test_that("get_signals sends after, limit and wait, and a large after in full", {
  sent <- capture({
    verdifax_get_signals(feed_client(), after = 12, limit = 500, wait = 25)
    verdifax_get_signals(feed_client(), after = 1e5, limit = 1)
  })
  expect_equal(sent[[1]]$query, list(after = "12", limit = "500", wait = "25"))
  expect_equal(sent[[2]]$query, list(after = "100000", limit = "1", wait = "0"))
})

test_that("get_signals with as_owner reads the owner key's /account/signals", {
  sent <- capture(result <- verdifax_get_signals(owner_client(), after = 3, wait = 5, as_owner = TRUE))
  expect_equal(sent[[1]]$method, "GET")
  expect_equal(sent[[1]]$path, "/account/signals")
  expect_equal(sent[[1]]$query, list(after = "3", wait = "5"))
  expect_equal(sent[[1]]$key, "owner")
  expect_length(result$events, 2)
})

test_that("a signals call's timeout is at least the wait plus 30 seconds", {
  sent <- capture({
    verdifax_get_signals(feed_client(timeout = 5), wait = 25)
    verdifax_get_signals(feed_client(timeout = 5))
    verdifax_get_signals(feed_client(timeout = 120), wait = 25)
    verdifax_get_signals(feed_client(), wait = 25)
  })
  expect_equal(sent[[1]]$timeout, 55)
  expect_equal(sent[[2]]$timeout, 30)
  expect_equal(sent[[3]]$timeout, 120)
  expect_equal(sent[[4]]$timeout, 90)
})

test_that("get_signals refuses bad arguments without a request", {
  sent <- capture({
    for (after in list(-1, 1.5, NA, Inf, "0", c(1, 2), TRUE, NULL, 2^53)) {
      expect_error(verdifax_get_signals(feed_client(), after = after), "after must be")
    }
    for (limit in list(0, 501, -1, 1.5, NA, Inf, "10", c(1, 2), TRUE)) {
      expect_error(verdifax_get_signals(feed_client(), limit = limit), "limit must be")
    }
    for (wait in list(-1, 26, 2.5, NA, Inf, "5", c(1, 2), TRUE, NULL)) {
      expect_error(verdifax_get_signals(feed_client(), wait = wait), "wait must be")
    }
    for (flag in list(NA, "yes", 1, c(TRUE, FALSE), NULL)) {
      expect_error(verdifax_get_signals(feed_client(), as_owner = flag), "as_owner")
    }
  })
  expect_length(sent, 0)
})

test_that("get_signals carries the client's retry policy, as every GET does", {
  req <- verdifax:::.signals_request(feed_client(), 0, NULL, 25, FALSE)
  expect_equal(req$policies$retry_max_tries, 4)
  expect_true(req$policies$retry_is_transient(httr2::response(status_code = 503)))
  expect_false(req$policies$retry_is_transient(httr2::response(status_code = 401)))
  off <- verdifax:::.signals_request(feed_client(max_retries = 0), 0, NULL, 25, FALSE)
  expect_null(off$policies$retry_max_tries)
  sent <- capture(verdifax_get_signals(feed_client(max_retries = 2)))
  expect_equal(sent[[1]]$retries, 3)
})

test_that("get_signals passes on the server's message", {
  respond <- function(req) json_response("{\"ok\":false,\"error\":\"a key may hold at most 2 waits open at once\"}", 429)
  capture(expect_error(
    verdifax_get_signals(feed_client(max_retries = 0), wait = 25), "at most 2 waits", class = "httr2_http_429"
  ), respond)
})


# ── Following the feed ──────────────────────────────────────────────────────

test_that("follow_signals follows next_after through two pages and an empty one until the caller stops", {
  pages <- list(
    function() signals_page(list(1L, 2L), 2L),
    function() signals_page(list(3L), 3L),
    function() signals_page(list(), 3L),
    function() signals_page(list(4L, 5L), 5L)
  )
  calls <- 0
  respond <- function(req) {
    calls <<- calls + 1
    pages[[calls]]()
  }
  seen <- c()
  sent <- capture(
    last <- verdifax_follow_signals(feed_client(), function(event) {
      seen <<- c(seen, event$data$sequence)
      event$data$sequence < 4
    }),
    respond
  )
  expect_equal(seen, c(1, 2, 3, 4))
  expect_equal(last, 4)
  expect_length(sent, 4)
  for (request in sent) {
    expect_equal(request$method, "GET")
    expect_equal(request$path, "/signals")
    expect_equal(request$query$wait, "25")
    expect_null(request$query$limit)
    expect_equal(request$timeout, 90)
  }
  expect_equal(vapply(sent, function(r) r$query$after, ""), c("0", "2", "3", "3"))
})

test_that("follow_signals starts at after, uses as_owner and keeps going when the handler returns NULL", {
  pages <- list(function() signals_page(list(8L), 8L), function() signals_page(list(9L), 9L))
  calls <- 0
  respond <- function(req) {
    calls <<- calls + 1
    pages[[calls]]()
  }
  sent <- capture(
    last <- verdifax_follow_signals(owner_client(), function(event) {
      if (event$data$sequence == 9) FALSE else NULL
    }, after = 7, wait = 10, as_owner = TRUE),
    respond
  )
  expect_equal(last, 9)
  expect_equal(sent[[1]]$path, "/account/signals")
  expect_equal(sent[[1]]$key, "owner")
  expect_equal(sent[[1]]$query, list(after = "7", wait = "10"))
  expect_equal(sent[[2]]$query$after, "8")
})

test_that("follow_signals stops mid-page when the handler returns FALSE", {
  seen <- c()
  sent <- capture(last <- verdifax_follow_signals(feed_client(), function(event) {
    seen <<- c(seen, event$data$sequence)
    FALSE
  }))
  expect_length(sent, 1)
  expect_equal(seen, 1)
  expect_equal(last, 1)
})

test_that("follow_signals reads every page with the client's retry policy", {
  calls <- 0
  respond <- function(req) {
    calls <<- calls + 1
    signals_page(list(calls), calls)
  }
  sent <- capture(verdifax_follow_signals(feed_client(max_retries = 5), function(event) {
    event$data$sequence < 3
  }), respond)
  expect_length(sent, 3)
  for (request in sent) {
    expect_equal(request$retries, 6)
  }
})

test_that("a 503 page that is not retried away stops following with the last sequence read", {
  calls <- 0
  respond <- function(req) {
    calls <<- calls + 1
    if (calls == 1) signals_page(list(1L), 1L) else json_response("{\"ok\":false,\"error\":\"busy\"}", 503)
  }
  sent <- capture(error <- tryCatch(
    verdifax_follow_signals(feed_client(), function(event) TRUE),
    error = identity
  ), respond)
  expect_s3_class(error, "verdifax_follow_error")
  expect_equal(error$after, 1)
  expect_s3_class(error$parent, "httr2_http_503")
  expect_equal(sent[[2]]$query$after, "1")
})

test_that("a failed page stops following with the last sequence read", {
  calls <- 0
  respond <- function(req) {
    calls <<- calls + 1
    if (calls == 1) signals_page(list(1L, 2L), 2L) else
      json_response("{\"ok\":false,\"error\":\"the key is revoked\"}", 401)
  }
  sent <- capture(error <- tryCatch(
    verdifax_follow_signals(feed_client(), function(event) TRUE),
    error = identity
  ), respond)
  expect_length(sent, 2)
  expect_s3_class(error, "verdifax_follow_error")
  expect_equal(error$after, 2)
  expect_match(conditionMessage(error), "stopped after sequence 2")
  expect_match(conditionMessage(error), "the key is revoked")
  expect_match(conditionMessage(error), "resume with after = 2")
  expect_s3_class(error$parent, "httr2_http_401")
})

test_that("a handler error stops following at the last event handled, so none is skipped", {
  sent <- capture(error <- tryCatch(
    verdifax_follow_signals(feed_client(), function(event) {
      if (event$data$sequence == 2) stop("disk full")
      TRUE
    }, after = 0),
    error = identity
  ))
  expect_length(sent, 1)
  expect_s3_class(error, "verdifax_follow_error")
  expect_equal(error$after, 1)
  expect_match(conditionMessage(error), "disk full")
  expect_equal(conditionMessage(error$parent), "disk full")
})

test_that("a page out of order stops following without skipping", {
  bad_pages <- list(
    function() json_response("{\"next_after\":2,\"newest\":2}"),
    function() json_response("{\"events\":[],\"newest\":2}"),
    function() signals_page(list(), 4L),
    function() signals_page(list(5L), 4L),
    function() signals_page(list(3L), 3L)
  )
  for (page in bad_pages) {
    sent <- capture(error <- tryCatch(
      verdifax_follow_signals(feed_client(), function(event) TRUE, after = 3),
      error = identity
    ), function(req) page())
    expect_s3_class(error, "verdifax_follow_error")
    expect_equal(error$after, 3)
    expect_length(sent, 1)
  }
  # next_after going back is refused too.
  capture(error <- tryCatch(
    verdifax_follow_signals(feed_client(), function(event) TRUE, after = 5),
    error = identity
  ), function(req) signals_page(list(), 4L))
  expect_equal(error$after, 5)
})

test_that("follow_signals with wait = 0 pauses after an empty page", {
  calls <- 0
  respond <- function(req) {
    calls <<- calls + 1
    if (calls == 1) signals_page(list(), 0L) else signals_page(list(1L), 1L)
  }
  started <- Sys.time()
  sent <- capture(verdifax_follow_signals(feed_client(), function(event) FALSE, wait = 0), respond)
  expect_gte(as.numeric(difftime(Sys.time(), started, units = "secs")), 0.9)
  expect_length(sent, 2)
  expect_equal(sent[[1]]$query$wait, "0")
})

test_that("follow_signals refuses bad arguments without a request", {
  sent <- capture({
    for (handler in list(NULL, "f", 1, list())) {
      expect_error(verdifax_follow_signals(feed_client(), handler), "handler")
    }
    for (after in list(-1, 1.5, NA, Inf, "0", NULL)) {
      expect_error(verdifax_follow_signals(feed_client(), identity, after = after), "after must be")
    }
    for (wait in list(-1, 26, 2.5, NA, "5", NULL)) {
      expect_error(verdifax_follow_signals(feed_client(), identity, wait = wait), "wait must be")
    }
    for (flag in list(NA, "yes", 1, NULL)) {
      expect_error(verdifax_follow_signals(feed_client(), identity, as_owner = flag), "as_owner")
    }
    for (on_head in list("f", 1, TRUE, list())) {
      expect_error(verdifax_follow_signals(feed_client(), identity, on_head = on_head), "on_head")
    }
    for (hash in list(strrep("A", 64), strrep("a", 63), c(strrep("a", 64), strrep("b", 64)), NA, 1, TRUE)) {
      expect_error(
        verdifax_follow_signals(feed_client(), identity, after = 3, after_event_hash = hash),
        "after_event_hash must be 64 lowercase hex characters"
      )
    }
  })
  expect_length(sent, 0)
})


# ── The feed's head (round 61, N23) ─────────────────────────────────────────

# Verdifax's statement of the feed's highest event, as the server serves it at
# the end of a page that reaches the feed's end. Each statement's hash is
# derived from its sequence and time, so a restated head has a fresh one.
feed_head <- function(sequence, stated_at = "2026-11-12T22:00:00Z",
                      statement = paste(sequence, stated_at), head_hash = event_hash_of(sequence)) {
  list(
    format = "verdifax.feed-head.v1", account = "account-7", sequence = sequence,
    head_hash = head_hash, stated_at = stated_at,
    head_statement_hash = as.character(openssl::sha256(statement)),
    anchor = list(
      kind = "receipt_anchor", receipt_kind = "feed_head",
      log_index = 40L, tree_size = 41L, inclusion_path = list(strrep("1", 64))
    )
  )
}

head_page <- function(sequences, next_after, head) {
  json_response(to_json(list(
    events = lapply(sequences, cloud_event), next_after = next_after, newest = next_after, head = head
  )))
}

test_that("get_signals returns the page's head with every field", {
  text <- to_json(list(
    events = list(cloud_event(8L), cloud_event(9L)), next_after = 9L, newest = 9L, head = feed_head(9L)
  ))
  sent <- capture(page <- verdifax_get_signals(feed_client(), after = 7), function(req) json_response(text))
  expect_length(sent, 1)
  expect_length(page$events, 2)
  expect_setequal(
    names(page$head),
    c("format", "account", "sequence", "head_hash", "stated_at", "head_statement_hash", "anchor")
  )
  expect_identical(page$head$format, "verdifax.feed-head.v1")
  expect_identical(page$head$account, "account-7")
  expect_equal(page$head$sequence, 9)
  expect_identical(page$head$head_hash, event_hash_of(9))
  expect_identical(page$head$stated_at, "2026-11-12T22:00:00Z")
  expect_identical(page$head$head_statement_hash, as.character(openssl::sha256("9 2026-11-12T22:00:00Z")))
  expect_identical(page$head$anchor$receipt_kind, "feed_head")
  expect_identical(page$head$anchor$inclusion_path, list(strrep("1", 64)))
  # The events are the events alone: the head is not one of them.
  expect_equal(vapply(page$events, function(e) e$data$sequence, numeric(1)), c(8, 9))
})

# A follow over `pages`, each a function returning a response, in turn.
follow_pages <- function(pages, handler, ...) {
  calls <- 0
  respond <- function(req) {
    calls <<- calls + 1
    pages[[calls]]()
  }
  heads <- list()
  result <- NULL
  sent <- capture(result <- tryCatch(
    verdifax_follow_signals(feed_client(), handler, on_head = function(head) {
      heads[[length(heads) + 1]] <<- head
      "ignored"
    }, ...),
    error = identity
  ), respond)
  list(result = result, heads = heads, sent = sent)
}

test_that("follow_signals never passes the head as an event and keeps it after its page's events", {
  restated <- feed_head(3L, stated_at = "2026-11-12T22:06:00Z")
  pages <- list(
    function() signals_page(list(1L, 2L), 2L),
    function() head_page(list(3L), 3L, feed_head(3L)),
    function() head_page(list(), 3L, feed_head(3L)),
    function() head_page(list(), 3L, restated),
    function() head_page(list(4L, 5L), 5L, feed_head(5L)),
    function() head_page(list(6L), 6L, feed_head(6L))
  )
  seen <- list()
  heads_when <- c()
  out <- follow_pages(pages, function(event) {
    seen[[length(seen) + 1]] <<- event
    event$data$sequence < 6
  })
  expect_length(out$sent, 6)
  expect_equal(vapply(seen, function(e) e$data$sequence, numeric(1)), c(1, 2, 3, 4, 5, 6))
  for (event in seen) {
    expect_identical(event$specversion, "1.0")
    expect_false("head_hash" %in% names(event))
  }
  # The same head served again on an idle read is not passed twice; a
  # restated one is. The head of the page the handler stopped on is not kept.
  expect_identical(out$heads, list(feed_head(3L), restated, feed_head(5L)))
  expect_equal(as.vector(out$result), 6)
  expect_identical(attr(out$result, "head"), feed_head(5L))
  expect_equal(vapply(out$sent, function(r) r$query$after, ""), c("0", "2", "3", "3", "3", "5"))
})

test_that("on_head is called only after every event of its page is handled", {
  order <- c()
  calls <- 0
  respond <- function(req) {
    calls <<- calls + 1
    if (calls == 1) head_page(list(1L, 2L), 2L, feed_head(2L)) else signals_page(list(3L), 3L)
  }
  capture(verdifax_follow_signals(feed_client(), function(event) {
    order <<- c(order, paste0("event ", event$data$sequence))
    event$data$sequence < 3
  }, on_head = function(head) order <<- c(order, paste0("head ", head$sequence))), respond)
  expect_identical(order, c("event 1", "event 2", "head 2", "event 3"))
})

test_that("follow_signals returns no head attribute when no head was kept", {
  capture(last <- verdifax_follow_signals(feed_client(), function(event) FALSE))
  expect_null(attr(last, "head"))
  expect_identical(last, 1L)
})

test_that("a head whose sequence is not the page's next_after is not kept", {
  for (sequence in c(4L, 6L)) {
    out <- follow_pages(list(
      function() head_page(list(5L), 5L, feed_head(sequence)),
      function() signals_page(list(6L), 6L)
    ), function(event) event$data$sequence < 6, after = 4)
    expect_length(out$heads, 0)
    expect_null(attr(out$result, "head"))
  }
  # A head with no whole sequence is not kept either.
  bad <- feed_head(5L)
  bad$sequence <- "5"
  out <- follow_pages(list(
    function() head_page(list(5L), 5L, bad),
    function() signals_page(list(6L), 6L)
  ), function(event) event$data$sequence < 6, after = 4)
  expect_length(out$heads, 0)
})

test_that("a head on a page the handler did not finish is not kept", {
  # Stopped mid-page.
  out <- follow_pages(list(function() head_page(list(1L, 2L), 2L, feed_head(2L))), function(event) FALSE)
  expect_length(out$heads, 0)
  expect_equal(as.vector(out$result), 1)
  expect_null(attr(out$result, "head"))
  # Stopped on the page's last event.
  out <- follow_pages(list(function() head_page(list(1L, 2L), 2L, feed_head(2L))), function(event) {
    event$data$sequence < 2
  })
  expect_length(out$heads, 0)
  expect_null(attr(out$result, "head"))
  # A handler error on the page: the error holds the head kept before it.
  out <- follow_pages(list(
    function() head_page(list(1L), 1L, feed_head(1L)),
    function() head_page(list(2L, 3L), 3L, feed_head(3L))
  ), function(event) if (event$data$sequence == 3) stop("disk full") else TRUE)
  expect_s3_class(out$result, "verdifax_follow_error")
  expect_equal(out$result$after, 2)
  expect_identical(out$heads, list(feed_head(1L)))
  expect_identical(out$result$head, feed_head(1L))
})

test_that("a head stating a lower sequence than the one kept does not replace it", {
  out <- follow_pages(list(
    function() head_page(list(6L), 6L, feed_head(6L)),
    function() head_page(list(), 6L, NULL),
    function() head_page(list(7L), 7L, NULL)
  ), function(event) event$data$sequence < 7)
  expect_identical(out$heads, list(feed_head(6L)))
  expect_identical(attr(out$result, "head"), feed_head(6L))
  kept <- feed_head(6L)
  lower <- feed_head(5L)
  expect_false(verdifax:::.newer_head(kept, lower, 5, event_hash_of(5)))
  expect_true(verdifax:::.newer_head(NULL, lower, 5, event_hash_of(5)))
  # The same statement is not kept again; a fresh one for its sequence is.
  expect_false(verdifax:::.newer_head(kept, feed_head(6L), 6, event_hash_of(6)))
  expect_true(verdifax:::.newer_head(kept, feed_head(6L, stated_at = "2026-11-12T22:06:00Z"), 6, event_hash_of(6)))
})

test_that("a follow error holds the head kept", {
  calls <- 0
  respond <- function(req) {
    calls <<- calls + 1
    if (calls == 1) head_page(list(1L), 1L, feed_head(1L)) else
      json_response("{\"ok\":false,\"error\":\"the key is revoked\"}", 401)
  }
  capture(error <- tryCatch(
    verdifax_follow_signals(feed_client(), function(event) TRUE),
    error = identity
  ), respond)
  expect_s3_class(error, "verdifax_follow_error")
  expect_equal(error$after, 1)
  expect_identical(error$head, feed_head(1L))
  capture(error <- tryCatch(
    verdifax_follow_signals(feed_client(), function(event) stop("disk full")),
    error = identity
  ))
  expect_null(error$head)
})

test_that("a follow error holds the event_hash of the last event handled, to resume with", {
  # A handler error on event 2: event 1 was the last handled.
  capture(error <- tryCatch(
    verdifax_follow_signals(feed_client(), function(event) if (event$data$sequence == 2) stop("disk full") else TRUE),
    error = identity
  ))
  expect_equal(error$after, 1)
  expect_identical(error$after_event_hash, event_hash_of(1))
  # A failed read after a page: its last event.
  calls <- 0
  respond <- function(req) {
    calls <<- calls + 1
    if (calls == 1) signals_page(list(1L, 2L), 2L) else json_response("{\"ok\":false,\"error\":\"busy\"}", 401)
  }
  capture(error <- tryCatch(verdifax_follow_signals(feed_client(), function(event) TRUE), error = identity), respond)
  expect_equal(error$after, 2)
  expect_identical(error$after_event_hash, event_hash_of(2))
  # A malformed page before any event: the hash given, or NULL with none.
  out_of_order <- function(req) signals_page(list(3L), 3L)
  capture(error <- tryCatch(
    verdifax_follow_signals(feed_client(), function(event) TRUE, after = 5, after_event_hash = event_hash_of(5)),
    error = identity
  ), out_of_order)
  expect_equal(error$after, 5)
  expect_identical(error$after_event_hash, event_hash_of(5))
  capture(error <- tryCatch(
    verdifax_follow_signals(feed_client(), function(event) TRUE, after = 5),
    error = identity
  ), out_of_order)
  expect_null(error$after_event_hash)
  # Resuming with both values keeps the head at the feed's end.
  heads <- list()
  calls <- 0
  respond <- function(req) {
    calls <<- calls + 1
    if (calls == 1) head_page(list(), 2L, feed_head(2L)) else json_response("{\"ok\":false,\"error\":\"busy\"}", 401)
  }
  capture(resumed <- tryCatch(verdifax_follow_signals(
    feed_client(), function(event) TRUE, after = 2, after_event_hash = event_hash_of(2),
    on_head = function(head) heads[[length(heads) + 1]] <<- head
  ), error = identity), respond)
  expect_identical(heads, list(feed_head(2L)))
  expect_identical(resumed$head, feed_head(2L))
  expect_identical(resumed$after_event_hash, event_hash_of(2))
})

test_that("an on_head error stops following at the page's last event, holding the head", {
  seen <- c()
  sent <- capture(error <- tryCatch(
    verdifax_follow_signals(
      feed_client(), function(event) {
        seen <<- c(seen, event$data$sequence)
        TRUE
      },
      after = 4, on_head = function(head) stop("cannot save the head")
    ),
    error = identity
  ), function(req) head_page(list(5L), 5L, feed_head(5L)))
  expect_length(sent, 1)
  expect_equal(seen, 5)
  expect_s3_class(error, "verdifax_follow_error")
  expect_equal(error$after, 5)
  expect_match(conditionMessage(error), "cannot save the head")
  expect_identical(error$head, feed_head(5L))
})

# The rule every SDK's follower keeps the head by, fixed by a vector the four
# SDKs share (round 61, R252). Each case's pages are served in order; once
# they are spent the next read fails, so the follow error holds the head
# kept. handle_until is the last event the caller finishes before it stops,
# and start, when given, is where it resumes: after `after`, passing the
# event_hash of event after_hash_of as after_event_hash when that is given.
# A head is {sequence, statement}: the head served has a head_statement_hash
# that is the SHA-256 of the statement label, so equal labels are the same
# statement.
test_that("vector: the feed head is kept and reported as sdk-feed-head-vector.json says", {
  vector <- jsonlite::fromJSON(testthat::test_path("sdk-feed-head-vector.json"), simplifyVector = FALSE)
  expect_gte(length(vector$cases), 13)
  vector_head <- function(head) {
    hash_of <- if (is.null(head$head_hash_of)) head$sequence else head$head_hash_of
    feed_head(as.integer(head$sequence), statement = head$statement, head_hash = event_hash_of(hash_of))
  }
  label_of <- function(head) {
    if (is.null(head)) {
      return(NULL)
    }
    labels <- unique(unlist(lapply(vector$cases, function(case) {
      lapply(case$pages, function(page) page$head$statement)
    })))
    found <- labels[vapply(labels, function(label) {
      identical(head$head_statement_hash, as.character(openssl::sha256(label)))
    }, logical(1))]
    list(sequence = head$sequence, statement = found)
  }
  expect_true(any(vapply(vector$cases, function(case) {
    any(vapply(case$pages, function(page) !is.null(page$head$head_hash_of), logical(1)))
  }, logical(1))))
  for (case in vector$cases) {
    pages <- lapply(case$pages, function(page) {
      events <- lapply(page$events, function(sequence) cloud_event(as.integer(sequence)))
      body <- list(events = events, next_after = page$next_after, newest = page$next_after)
      if (!is.null(page$head)) {
        body$head <- vector_head(page$head)
      }
      to_json(body)
    })
    calls <- 0
    respond <- function(req) {
      calls <<- calls + 1
      if (calls <= length(pages)) json_response(pages[[calls]]) else
        json_response("{\"ok\":false,\"error\":\"no more pages in this case\"}", 410)
    }
    reported <- list()
    after <- if (is.null(case$start)) 0 else case$start$after
    after_hash <- if (!is.null(case$start$after_hash_of)) event_hash_of(case$start$after_hash_of)
    capture(result <- tryCatch(
      verdifax_follow_signals(feed_client(), function(event) {
        is.null(case$handle_until) || event$data$sequence < case$handle_until
      }, after = after, after_event_hash = after_hash, on_head = function(head) reported[[length(reported) + 1]] <<- head),
      error = identity
    ), respond)
    stopped_at <- if (inherits(result, "verdifax_follow_error")) result$after else as.vector(result)
    expect_equal(stopped_at, if (is.null(case$handle_until)) {
      max(c(after, unlist(lapply(case$pages, function(page) page$events))))
    } else {
      case$handle_until
    }, info = case$name)
    if (is.null(case$handle_until)) {
      expect_s3_class(result, "verdifax_follow_error")
      expect_match(conditionMessage(result), "no more pages in this case")
      kept <- result$head
    } else {
      expect_equal(as.vector(result), case$handle_until, info = case$name)
      kept <- attr(result, "head")
    }
    expected_kept <- if (is.null(case$expected_kept)) NULL else vector_head(case$expected_kept)
    expect_identical(kept, expected_kept, info = case$name)
    expect_identical(label_of(kept), case$expected_kept, info = case$name)
    expect_identical(lapply(reported, label_of), case$expected_reported, info = case$name)
    expect_equal(calls, length(pages) + if (is.null(case$handle_until)) 1 else 0, info = case$name)
  }
})

test_that("a page whose head is not an object stops following without handling its events", {
  for (head in list("head", 7L, list(1L, 2L))) {
    seen <- c()
    text <- to_json(list(events = list(cloud_event(1L)), next_after = 1L, newest = 1L, head = head))
    sent <- capture(error <- tryCatch(
      verdifax_follow_signals(feed_client(), function(event) {
        seen <<- c(seen, event$data$sequence)
        TRUE
      }),
      error = identity
    ), function(req) json_response(text))
    expect_s3_class(error, "verdifax_follow_error")
    expect_match(conditionMessage(error), "head that is not an object")
    expect_equal(error$after, 0)
    expect_null(seen)
    expect_length(sent, 1)
  }
})


# ── Feed keys ───────────────────────────────────────────────────────────────

test_that("create_feed_key posts the name and, when given, expires_at", {
  sent <- capture({
    result <- verdifax_create_feed_key(owner_client(), "siem")
    verdifax_create_feed_key(owner_client(), "siem", expires_at = "2027-01-01T00:00:00Z")
  })
  expect_equal(sent[[1]]$method, "POST")
  expect_equal(sent[[1]]$path, "/account/feed-keys")
  expect_equal(sent[[1]]$key, "owner")
  expect_equal(sent[[1]]$json, "{\"name\":\"siem\"}")
  expect_equal(sent[[2]]$json, "{\"name\":\"siem\",\"expires_at\":\"2027-01-01T00:00:00Z\"}")
  expect_equal(result, parsed(.feed_key_reply))
  expect_equal(result$secret, "vfx_feed")
})

test_that("create_feed_key refuses bad arguments without a request", {
  sent <- capture({
    for (name in list("", NA_character_, c("a", "b"), 5, NULL)) {
      expect_error(verdifax_create_feed_key(owner_client(), name), "name")
    }
    for (expiry in list("", NA_character_, 5, c("a", "b"))) {
      expect_error(verdifax_create_feed_key(owner_client(), "siem", expires_at = expiry), "expires_at")
    }
  })
  expect_length(sent, 0)
})

test_that("revoke_feed_key calls DELETE /account/feed-keys/{id} and passes on a 404", {
  sent <- capture({
    result <- verdifax_revoke_feed_key(owner_client(), 12)
    verdifax_revoke_feed_key(owner_client(), 1e5)
  })
  expect_equal(sent[[1]]$method, "DELETE")
  expect_equal(sent[[1]]$path, "/account/feed-keys/12")
  expect_null(sent[[1]]$body)
  expect_equal(sent[[2]]$path, "/account/feed-keys/100000")
  expect_equal(result, list(ok = TRUE, id = 12L, revoked = TRUE))
  respond <- function(req) json_response("{\"ok\":false,\"error\":\"no such feed key in this account\"}", 404)
  sent <- capture(expect_error(
    verdifax_revoke_feed_key(owner_client(), 9), "no such feed key", class = "httr2_http_404"
  ), respond)
  expect_length(sent, 1)
  sent <- capture(for (id in list(0, -1, 1.5, NA, Inf, "3", c(1, 2), TRUE, NULL)) {
    expect_error(verdifax_revoke_feed_key(owner_client(), id), "id must be a positive whole number")
  })
  expect_length(sent, 0)
})


# ── Webhooks ────────────────────────────────────────────────────────────────

test_that("create_webhook posts the url and types, always as a JSON array", {
  sent <- capture({
    result <- verdifax_create_webhook(owner_client(), "https://hooks.example.com/verdifax",
      types = c("run.refused", "run.halted"))
    verdifax_create_webhook(owner_client(), "https://hooks.example.com/verdifax", types = "run.failed")
    verdifax_create_webhook(owner_client(), "https://hooks.example.com/verdifax")
    verdifax_create_webhook(owner_client(), "https://hooks.example.com/verdifax", types = character(0))
    verdifax_create_webhook(owner_client(), "https://hooks.example.com/verdifax", types = .kinds)
  })
  expect_equal(sent[[1]]$method, "POST")
  expect_equal(sent[[1]]$path, "/account/webhooks")
  expect_equal(sent[[1]]$key, "owner")
  expect_equal(
    sent[[1]]$json,
    "{\"url\":\"https://hooks.example.com/verdifax\",\"types\":[\"run.refused\",\"run.halted\"]}"
  )
  expect_equal(
    sent[[2]]$json,
    "{\"url\":\"https://hooks.example.com/verdifax\",\"types\":[\"run.failed\"]}"
  )
  expect_equal(sent[[3]]$json, "{\"url\":\"https://hooks.example.com/verdifax\"}")
  expect_equal(sent[[4]]$json, sent[[3]]$json)
  expect_equal(unlist(sent[[5]]$body$types), .kinds)
  expect_equal(result, parsed(.webhook_reply))
  expect_match(result$secret, "^whsec_")
})

test_that("create_webhook refuses a bad url or types without a request", {
  sent <- capture({
    for (url in list("http://hooks.example.com", "hooks.example.com", "https://", "", NA_character_,
                     c("https://a", "https://b"), 5, NULL, "HTTPS://hooks.example.com")) {
      expect_error(verdifax_create_webhook(owner_client(), url), "url must be")
    }
    for (types in list("run", "com.verdifax.run.refused", "Run.Refused", c("run.refused", NA), 5,
                       list("run.refused"), TRUE)) {
      expect_error(
        verdifax_create_webhook(owner_client(), "https://hooks.example.com", types = types), "types must be"
      )
    }
    expect_error(
      verdifax_create_webhook(owner_client(), "https://hooks.example.com", types = c("run.failed", "run.failed")),
      "twice"
    )
  })
  expect_length(sent, 0)
})

test_that("create_webhook passes on the server's 400, 409 and 503", {
  for (case in list(
    list(400, "the address must not be a private address"),
    list(409, "an account may hold 10 webhook subscriptions"),
    list(503, "webhooks need the deployment's KMS key")
  )) {
    respond <- function(req) json_response(to_json(list(ok = FALSE, error = case[[2]])), case[[1]])
    sent <- capture(expect_error(
      verdifax_create_webhook(owner_client(), "https://hooks.example.com"),
      case[[2]], fixed = TRUE, class = paste0("httr2_http_", case[[1]])
    ), respond)
    expect_length(sent, 1)
  }
})

test_that("list_webhooks calls GET /account/webhooks", {
  sent <- capture(result <- verdifax_list_webhooks(owner_client()))
  expect_equal(sent[[1]]$method, "GET")
  expect_equal(sent[[1]]$path, "/account/webhooks")
  expect_equal(sent[[1]]$key, "owner")
  expect_null(sent[[1]]$body)
  expect_equal(result, parsed(.webhooks_reply))
})

test_that("delete_webhook calls DELETE /account/webhooks/{id}", {
  sent <- capture(result <- verdifax_delete_webhook(owner_client(), 4))
  expect_equal(sent[[1]]$method, "DELETE")
  expect_equal(sent[[1]]$path, "/account/webhooks/4")
  expect_null(sent[[1]]$body)
  expect_equal(result, list(ok = TRUE, id = 4L, deleted = TRUE))
  sent <- capture(for (id in list(0, -1, 1.5, NA, Inf, "3", c(1, 2), TRUE, NULL)) {
    expect_error(verdifax_delete_webhook(owner_client(), id), "id must be a positive whole number")
  })
  expect_length(sent, 0)
})

test_that("list_webhook_deliveries calls GET /account/webhooks/{id}/deliveries with limit", {
  sent <- capture({
    result <- verdifax_list_webhook_deliveries(owner_client(), 4)
    verdifax_list_webhook_deliveries(owner_client(), 4, limit = 500)
  })
  expect_equal(sent[[1]]$method, "GET")
  expect_equal(sent[[1]]$path, "/account/webhooks/4/deliveries")
  expect_equal(sent[[1]]$query, NULL)
  expect_equal(sent[[2]]$query, list(limit = "500"))
  expect_equal(result, parsed(.deliveries_reply))
  sent <- capture({
    for (id in list(0, 1.5, NA, "4", NULL)) {
      expect_error(verdifax_list_webhook_deliveries(owner_client(), id), "id must be")
    }
    for (limit in list(0, 501, 1.5, NA, "10", c(1, 2))) {
      expect_error(verdifax_list_webhook_deliveries(owner_client(), 4, limit = limit), "limit must be")
    }
  })
  expect_length(sent, 0)
})


# ── Failure receipts ────────────────────────────────────────────────────────

test_that("get_failure_receipt returns the server's exact text from the member route", {
  text <- "{\"ok\":true,\"run_id\":42,\"failure_receipt\":{\"seq\": 9007199254740993 },\"receipt_anchor\":{}}\n"
  sent <- capture(
    result <- verdifax_get_failure_receipt(member_client(), 42),
    function(req) json_response(text)
  )
  expect_equal(sent[[1]]$method, "GET")
  expect_equal(sent[[1]]$path, "/runs/42/failure-receipt")
  expect_equal(sent[[1]]$key, "member")
  expect_null(sent[[1]]$body)
  expect_identical(result, text)
})

test_that("get_failure_receipt passes on a 404 and refuses a bad run id", {
  respond <- function(req) json_response("{\"ok\":false,\"error\":\"this run has no failure receipt\"}", 404)
  sent <- capture(expect_error(
    verdifax_get_failure_receipt(member_client(), 7), "no failure receipt", class = "httr2_http_404"
  ), respond)
  expect_length(sent, 1)
  sent <- capture(for (id in list(0, -1, 1.5, NA, Inf, "42", c(1, 2), TRUE, NULL)) {
    expect_error(verdifax_get_failure_receipt(member_client(), id), "run_id")
  })
  expect_length(sent, 0)
})


# ── The event hash ──────────────────────────────────────────────────────────

test_that("vector: signal_event_hash", {
  expect_equal(
    verdifax_signal_event_hash(
      .vector$signal_kind, .vector$signal_entry_hash, .vector$signal_account,
      .vector$signal_sequence, .vector$signal_previous_hash
    ),
    .vector$signal_event_hash
  )
})

test_that("signal_event_hash is the SHA-256 of the zero-joined fields", {
  expected <- paste(as.character(openssl::sha256(zero_joined(list(
    "verdifax.signal.v1", "key.created", strrep("a", 64), "account-31", "100000", strrep("0", 64)
  )))), collapse = "")
  expect_equal(
    verdifax_signal_event_hash("key.created", strrep("a", 64), "account-31", 1e5, strrep("0", 64)),
    expected
  )
})

test_that("signal_event_hash hashes a kind it does not know, as the other SDKs do", {
  for (kind in c("run.paused", "run", "com.verdifax.run.refused", "")) {
    expected <- paste(as.character(openssl::sha256(zero_joined(list(
      "verdifax.signal.v1", kind, .vector$signal_entry_hash, .vector$signal_account, "12",
      .vector$signal_previous_hash
    )))), collapse = "")
    expect_equal(
      verdifax_signal_event_hash(
        kind, .vector$signal_entry_hash, .vector$signal_account, 12, .vector$signal_previous_hash
      ),
      expected
    )
  }
  # Webhook types still take only the known kinds.
  expect_error(verdifax:::.webhook_types("run.paused"), "types must be signal kinds")
})

test_that("signal_event_hash refuses bad fields", {
  good <- list(.vector$signal_kind, .vector$signal_entry_hash, .vector$signal_account, 12, .vector$signal_previous_hash)
  call <- function(i, value) {
    args <- good
    args[i] <- list(value)
    do.call(verdifax_signal_event_hash, args)
  }
  for (kind in list(NA_character_, NULL, 5, character(0), c("run.refused", "run.halted"))) {
    expect_error(call(1, kind), "kind")
  }
  expect_error(call(2, strrep("D", 64)), "entry_hash")
  for (account in list("account-0", "api-key-7", "7", NA_character_, NULL)) {
    expect_error(call(3, account), "account")
  }
  for (sequence in list(0, -1, 1.5, NA, Inf, "12", NULL, 2^53)) {
    expect_error(call(4, sequence), "sequence")
  }
  expect_error(call(5, strrep("e", 63)), "previous_signal_hash")
})


# ── Checking a webhook ──────────────────────────────────────────────────────

vector_headers <- function() {
  list(
    "webhook-id" = .vector$webhook_id,
    "webhook-timestamp" = .vector$webhook_timestamp,
    "webhook-signature" = .vector$webhook_signature
  )
}

vector_now <- function(offset = 0) as.numeric(.vector$webhook_timestamp) + offset

verify_vector <- function(headers = vector_headers(), body = .vector$webhook_body,
                          secret = .vector$webhook_secret, now = vector_now(), ...) {
  verdifax_verify_webhook(headers, body, secret, now = now, ...)
}

# One byte of a string changed.
flip <- function(text, at = 1) {
  bytes <- charToRaw(text)
  bytes[at] <- if (bytes[at] == charToRaw("A")) charToRaw("B") else charToRaw("A")
  rawToChar(bytes)
}

test_that("vector: verify_webhook accepts the delivery and returns the CloudEvent", {
  event <- verify_vector()
  expect_equal(event, parsed(.vector$webhook_body))
  expect_equal(event$id, "account-7/12")
  expect_equal(event$type, "com.verdifax.run.refused")
  expect_equal(verify_vector(body = charToRaw(.vector$webhook_body)), event)
  expect_equal(verify_vector(now = as.POSIXct(vector_now(), origin = "1970-01-01", tz = "UTC")), event)
})

test_that("verify_webhook matches header names whatever their case, as a list or a vector", {
  headers <- vector_headers()
  names(headers) <- c("Webhook-Id", "WEBHOOK-TIMESTAMP", "webhook-Signature")
  expect_equal(verify_vector(headers = headers)$id, "account-7/12")
  expect_equal(verify_vector(headers = unlist(headers))$id, "account-7/12")
  extra <- c(list("Content-Type" = "application/json"), vector_headers())
  expect_equal(verify_vector(headers = extra)$id, "account-7/12")
})

test_that("one byte changed in the body, id, timestamp or signature fails", {
  body <- .vector$webhook_body
  for (at in c(1, 20, nchar(body))) {
    expect_error(verify_vector(body = flip(body, at)), "no v1 signature", class = "verdifax_webhook_error")
  }
  raw_body <- charToRaw(body)
  raw_body[5] <- xor(raw_body[5], as.raw(1))
  expect_error(verify_vector(body = raw_body), "no v1 signature")
  headers <- vector_headers()
  headers[["webhook-id"]] <- flip(headers[["webhook-id"]])
  expect_error(verify_vector(headers = headers), "no v1 signature")
  headers <- vector_headers()
  headers[["webhook-timestamp"]] <- "1794096001"
  expect_error(verify_vector(headers = headers), "no v1 signature")
  headers <- vector_headers()
  headers[["webhook-signature"]] <- flip(headers[["webhook-signature"]], 10)
  expect_error(verify_vector(headers = headers), "no v1 signature")
})

test_that("a timestamp more than the tolerance away fails, in either direction", {
  expect_error(verify_vector(now = vector_now(301)), "more than 300 seconds", class = "verdifax_webhook_error")
  expect_error(verify_vector(now = vector_now(-301)), "more than 300 seconds")
  expect_equal(verify_vector(now = vector_now(300))$id, "account-7/12")
  expect_equal(verify_vector(now = vector_now(-300))$id, "account-7/12")
  expect_equal(verify_vector(now = vector_now(301), tolerance_seconds = 600)$id, "account-7/12")
  expect_error(verify_vector(now = vector_now(11), tolerance_seconds = 10), "more than 10 seconds")
  expect_error(verdifax_verify_webhook(vector_headers(), .vector$webhook_body, .vector$webhook_secret),
    "more than 300 seconds")
})

test_that("a second, wrong v1 entry beside the right one still passes", {
  wrong <- paste0("v1,", jsonlite::base64_enc(as.raw(rep(7L, 32))))
  for (signature in c(
    paste(wrong, .vector$webhook_signature),
    paste(.vector$webhook_signature, wrong),
    paste("v2,abc", .vector$webhook_signature),
    paste("v1,not-base64", .vector$webhook_signature)
  )) {
    headers <- vector_headers()
    headers[["webhook-signature"]] <- signature
    expect_equal(verify_vector(headers = headers)$id, "account-7/12")
  }
  headers <- vector_headers()
  headers[["webhook-signature"]] <- wrong
  expect_error(verify_vector(headers = headers), "no v1 signature in webhook-signature matches")
  headers[["webhook-signature"]] <- sub("^v1,", "v2,", .vector$webhook_signature)
  expect_error(verify_vector(headers = headers), "holds no v1 signature")
})

test_that("a wrong secret or a wrong secret prefix fails, and the secret is never shown", {
  secret <- .vector$webhook_secret
  for (bad in c(sub("^whsec_", "", secret), sub("^whsec_", "whsec-", secret), sub("^whsec_", "WHSEC_", secret))) {
    error <- tryCatch(verify_vector(secret = bad), error = identity)
    expect_s3_class(error, "verdifax_webhook_error")
    expect_match(conditionMessage(error), "must be a single string starting with whsec_")
    expect_false(grepl(sub("^whsec_", "", secret), conditionMessage(error), fixed = TRUE))
  }
  expect_error(verify_vector(secret = "whsec_not base64!"), "after whsec_ must be base64")
  expect_error(verify_vector(secret = "whsec_"), "after whsec_ must be base64")
  other <- paste0("whsec_", jsonlite::base64_enc(as.raw(rep(9L, 32))))
  error <- tryCatch(verify_vector(secret = other), error = identity)
  expect_match(conditionMessage(error), "no v1 signature")
  expect_false(grepl(other, conditionMessage(error), fixed = TRUE))
  for (bad in list(NULL, NA_character_, 5, c(secret, secret))) {
    expect_error(verify_vector(secret = bad), "whsec_")
  }
})

test_that("missing or malformed headers and arguments say which check failed", {
  for (name in c("webhook-id", "webhook-timestamp", "webhook-signature")) {
    headers <- vector_headers()
    headers[[name]] <- NULL
    expect_error(verify_vector(headers = headers), paste("the", name, "header is missing"))
  }
  headers <- c(vector_headers(), list("Webhook-Id" = .vector$webhook_id))
  expect_error(verify_vector(headers = headers), "given more than once")
  headers <- vector_headers()
  headers[["webhook-timestamp"]] <- "2026-11-07T12:00:00Z"
  expect_error(verify_vector(headers = headers), "whole seconds")
  headers[["webhook-timestamp"]] <- ""
  expect_error(verify_vector(headers = headers), "single non-empty string")
  expect_error(verify_vector(headers = unname(vector_headers())), "named list")
  expect_error(verify_vector(headers = NULL), "named list")
  for (body in list(NULL, 5, NA_character_, c("a", "b"), list("a"))) {
    expect_error(verify_vector(body = body), "raw bytes received")
  }
  for (now in list("now", NA, c(1, 2), NULL)) {
    expect_error(verify_vector(now = now), "now must be")
  }
  for (tolerance in list(-1, NA, "300", Inf, NULL)) {
    expect_error(verify_vector(tolerance_seconds = tolerance), "tolerance_seconds")
  }
})

test_that("a signed body that is not a JSON object fails after the signature check", {
  key <- jsonlite::base64_dec(sub("^whsec_", "", .vector$webhook_secret))
  sign <- function(body) {
    mac <- openssl::sha256(c(charToRaw(paste0(.vector$webhook_id, ".", .vector$webhook_timestamp, ".")),
      charToRaw(body)), key = key)
    paste0("v1,", jsonlite::base64_enc(unclass(mac)))
  }
  for (body in c("not json", "[1,2]", "\"text\"")) {
    headers <- vector_headers()
    headers[["webhook-signature"]] <- sign(body)
    expect_error(verify_vector(headers = headers, body = body), "not a JSON CloudEvent")
  }
})

test_that("a correctly signed body whose id differs from webhook-id fails that check", {
  key <- jsonlite::base64_dec(sub("^whsec_", "", .vector$webhook_secret))
  sign <- function(body) {
    mac <- openssl::sha256(c(charToRaw(paste0(.vector$webhook_id, ".", .vector$webhook_timestamp, ".")),
      charToRaw(body)), key = key)
    paste0("v1,", jsonlite::base64_enc(unclass(mac)))
  }
  original <- paste0("\"id\":\"", .vector$webhook_id, "\"")
  expect_true(grepl(original, .vector$webhook_body, fixed = TRUE))
  bodies <- c(
    sub(original, "\"id\":\"account-7/13\"", .vector$webhook_body, fixed = TRUE),
    sub(original, "\"id\":\"\"", .vector$webhook_body, fixed = TRUE),
    sub(original, "\"id\":12", .vector$webhook_body, fixed = TRUE),
    sub(original, "\"id\":null", .vector$webhook_body, fixed = TRUE),
    sub(original, "\"id\":[\"account-7/12\"]", .vector$webhook_body, fixed = TRUE),
    sub(paste0(original, ","), "", .vector$webhook_body, fixed = TRUE),
    sub("}$", ",\"id\":\"account-7/13\"}", .vector$webhook_body)
  )
  for (body in bodies) {
    expect_false(identical(body, .vector$webhook_body))
    headers <- vector_headers()
    headers[["webhook-signature"]] <- sign(body)
    failure <- tryCatch(verify_vector(headers = headers, body = body), error = function(e) e)
    expect_s3_class(failure, "verdifax_webhook_error")
    expect_match(conditionMessage(failure), "the event id in the body does not match webhook-id", fixed = TRUE)
    expect_false(grepl(sub("^whsec_", "", .vector$webhook_secret), conditionMessage(failure), fixed = TRUE))
  }
})

test_that("the constant-time comparison compares every byte and refuses a length mismatch", {
  expected <- as.raw(1:32)
  expect_true(verdifax:::.constant_time_equal(expected, as.raw(1:32)))
  for (i in c(1, 16, 32)) {
    other <- expected
    other[i] <- xor(other[i], as.raw(1))
    expect_false(verdifax:::.constant_time_equal(expected, other))
  }
  expect_false(verdifax:::.constant_time_equal(expected, as.raw(1:31)))
  expect_false(verdifax:::.constant_time_equal(expected, c(as.raw(1:32), as.raw(0))))
  expect_false(verdifax:::.constant_time_equal(expected, raw(0)))
})


# ── Parity ──────────────────────────────────────────────────────────────────

test_that("every signal route and helper in sdk-parity.json has its R function", {
  parity <- jsonlite::fromJSON(testthat::test_path("sdk-parity.json"), simplifyVector = FALSE)
  routes <- c(
    "GET /signals", "GET /account/signals", "POST /account/feed-keys", "DELETE /account/feed-keys/{id}",
    "POST /account/webhooks", "GET /account/webhooks", "DELETE /account/webhooks/{id}",
    "GET /account/webhooks/{id}/deliveries", "GET /runs/{id}/failure-receipt"
  )
  for (route in routes) {
    names <- unlist(parity$routes[[route]]$r)
    expect_length(names, 1)
    expect_true(names %in% getNamespaceExports("verdifax"), info = route)
  }
  for (helper in c("follow_signals", "signal_event_hash", "verify_webhook")) {
    name <- parity$helpers[[helper]]$r
    expect_true(name %in% getNamespaceExports("verdifax"), info = helper)
  }
  expect_match(parity$notes$signal_feed, "follow_signals")
})

test_that("verdifax_pending_signoffs lists required runs without an approval in force", {
  ev <- function(seq, kind, entry) list(id = paste0("account-7/", seq), data = list(kind = kind, sequence = seq, entry = entry))
  so <- function(run, decision, kind) list(decision = decision, target = list(kind = kind, run_id = run))
  events <- list(
    ev(1, "run.sealed", list(run_id = 10, signoff_required = TRUE)),
    ev(2, "run.sealed", list(run_id = 11)),
    ev(3, "run.sealed", list(run_id = 12, signoff_required = TRUE)),
    ev(4, "run.sealed", list(run_id = 13, signoff_required = TRUE)),
    ev(5, "signoff.recorded", so(10, "approve", "record")),
    ev(6, "signoff.recorded", so(12, "approve", "record")),
    ev(7, "signoff.recorded", so(12, "reject", "record")),
    ev(8, "signoff.recorded", so(13, "approve", "receipt"))
  )
  expect_identical(verdifax_pending_signoffs(events), c(12L, 13L))
  expect_error(verdifax_pending_signoffs(list(ev(1, "run.sealed", list()))), "names no run")
})

# Round 59, N15 and N19: a job sign-off on a run's record counts, and the
# job's decision governs the record's own, as the verifier reads it.
test_that("verdifax_pending_signoffs reads a job sign-off as the verifier does", {
  ev <- function(seq, kind, entry) list(id = paste0("account-7/", seq), data = list(kind = kind, sequence = seq, entry = entry))
  so <- function(run, decision, kind) list(decision = decision, target = list(kind = kind, run_id = run))
  events <- list(
    ev(1, "run.sealed", list(run_id = 20, signoff_required = TRUE)),
    ev(2, "run.sealed", list(run_id = 21, signoff_required = TRUE)),
    ev(3, "run.sealed", list(run_id = 22, signoff_required = TRUE)),
    ev(4, "signoff.recorded", so(20, "approve", "job")),
    ev(5, "signoff.recorded", so(21, "reject", "job")),
    ev(6, "signoff.recorded", so(21, "approve", "record")),
    ev(7, "signoff.recorded", so(22, "reject", "record")),
    ev(8, "signoff.recorded", so(22, "approve", "job"))
  )
  # 20: approved by its job. 21: the job's rejection governs its own
  # approval. 22: the job's approval governs its own rejection.
  expect_identical(verdifax_pending_signoffs(events), 21L)
})

# Round 61: the server keeps a run.sealed event's own entry when the run's
# record is deleted, so a run.sealed event that names no run, a NULL entry
# included, is refused as before; the run.deleted event leaves the run out.
test_that("verdifax_pending_signoffs refuses a run.sealed event with a NULL entry and reads a deleted run's events", {
  ev <- function(seq, kind, entry, deleted = NULL) {
    list(id = paste0("account-7/", seq), data = c(list(kind = kind, sequence = seq, entry = entry), if (!is.null(deleted)) list(deleted = deleted)))
  }
  tombstone <- function(run) list(format = "verdifax.run-deletion.v1", decided_by = "owner", run_id = run, record_hash = strrep("a", 64), log_entries = list(strrep("1", 64)))
  # A deleted run's run.sealed event keeps its entry; its run.deleted event
  # leaves the run out.
  events <- list(
    ev(1, "run.sealed", list(run_id = 50, signoff_required = TRUE)),
    ev(2, "run.sealed", list(run_id = 51, signoff_required = TRUE)),
    ev(3, "run.deleted", tombstone(50))
  )
  expect_identical(verdifax_pending_signoffs(events), 51L)
  expect_identical(verdifax_pending_signoffs(events[1:2]), c(50L, 51L))
  # A run.sealed event with a NULL entry is refused, with or without a
  # tombstone beside it, as read from the server or built here.
  expect_error(verdifax_pending_signoffs(list(ev(1, "run.sealed", NULL))), "the run.sealed entry of event account-7/1 names no run")
  expect_error(verdifax_pending_signoffs(list(ev(1, "run.sealed", NULL, tombstone(50)), events[[3]])), "the run.sealed entry of event account-7/1 names no run")
  text <- "{\"id\":\"account-7/1\",\"data\":{\"kind\":\"run.sealed\",\"sequence\":1,\"entry\":null,\"deleted\":{\"run_id\":50}}}"
  expect_error(verdifax_pending_signoffs(list(jsonlite::fromJSON(text, simplifyVector = FALSE))), "names no run")
})

# The rule every SDK's pending sign-offs helper answers by, fixed by a vector
# the four SDKs share (round 61, R257). Each abstract event becomes a served
# CloudEvent as the other feed tests build them; entry and deleted are kept
# exactly, null included.
test_that("vector: pending sign-offs answer as sdk-pending-signoffs-vector.json says", {
  vector <- jsonlite::fromJSON(testthat::test_path("sdk-pending-signoffs-vector.json"), simplifyVector = FALSE)
  expect_gte(length(vector$cases), 8)
  for (case in vector$cases) {
    events <- lapply(seq_along(case$events), function(i) {
      abstract <- case$events[[i]]
      event <- cloud_event(i, abstract$kind)
      event$data["entry"] <- list(abstract$entry)
      if (!is.null(abstract$deleted)) {
        event$data$deleted <- abstract$deleted
      }
      event
    })
    # Served as JSON and read back, as a page of the feed is.
    page <- jsonlite::fromJSON(to_json(list(events = events)), simplifyVector = FALSE)
    if (isTRUE(case$expected_error)) {
      expect_error(verdifax_pending_signoffs(page$events), "names no run", info = case$name)
    } else {
      expect_identical(
        verdifax_pending_signoffs(page$events),
        as.integer(unlist(case$expected_pending)) %||% integer(0),
        info = case$name
      )
    }
  }
})

# Round 60: a deleted record has nothing left to sign off.
test_that("verdifax_pending_signoffs leaves out a run whose deletion is in the feed", {
  ev <- function(seq, kind, entry) list(id = paste0("account-7/", seq), data = list(kind = kind, sequence = seq, entry = entry))
  deletion <- function(run) list(format = "verdifax.run-deletion.v1", decided_by = "owner", run_id = run, record_hash = strrep("a", 64))
  events <- list(
    ev(1, "run.sealed", list(run_id = 30, signoff_required = TRUE)),
    ev(2, "run.sealed", list(run_id = 31, signoff_required = TRUE)),
    ev(3, "run.deleted", deletion(30)),
    ev(4, "run.deleted", deletion(99))
  )
  expect_identical(verdifax_pending_signoffs(events), 31L)
  # At any place in the events given, even before the run's sealing.
  expect_identical(verdifax_pending_signoffs(events[c(3, 1, 2)]), 31L)
  # A Verdifax deletion counts the same.
  admin <- events
  admin[[3]]$data$entry$decided_by <- "verdifax_admin"
  expect_identical(verdifax_pending_signoffs(admin), 31L)
  expect_identical(verdifax_pending_signoffs(events[1:2]), c(30L, 31L))
  expect_error(verdifax_pending_signoffs(list(ev(1, "run.deleted", list()))), "names no run")
})

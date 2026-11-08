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
      previous_signal_hash = strrep("e", 64), event_hash = strrep("d", 64), run_id = 42L,
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
  })
  expect_length(sent, 0)
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

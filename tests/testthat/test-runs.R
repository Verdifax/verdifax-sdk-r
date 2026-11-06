# Run retrieval, evidence export and batch runs. Requests are captured
# by a mock, so nothing reaches the network.

.program_id <- strrep("1", 64)
.registry_record_hash <- strrep("2", 64)
.row <- list(
  payload = "hello",
  program_id = .program_id,
  route_id = "r",
  registry_record_hash = .registry_record_hash
)
.csv <- "run_id,created_at,status\n1,2026-11-05T00:00:00Z,ok\n"

need_sodium <- function() {
  if (!nzchar(Sys.getenv("CI"))) {
    testthat::skip_if_not_installed("sodium")
  }
}

test_client <- function(signing_key = NULL) {
  verdifax_client(base_url = "http://mock.invalid", api_key = "k", signing_key = signing_key)
}

json_response <- function(text, status = 200) {
  httr2::response(
    status_code = status,
    headers = "Content-Type: application/json",
    body = charToRaw(text)
  )
}

# Runs `code`, answers each request with `respond`, and returns what was
# sent, decoded from the JSON the request would put on the wire.
capture <- function(code, respond = function(req) json_response("{\"ok\":true}")) {
  sent <- list()
  mock <- function(req) {
    body <- httr2::req_get_body(req)
    json <- if (is.null(body)) NULL else jsonlite::toJSON(body, auto_unbox = TRUE)
    sent[[length(sent) + 1]] <<- list(
      method = httr2::req_get_method(req),
      url = httr2::url_parse(httr2::req_get_url(req)),
      key = httr2::req_get_headers(req, "reveal")[["X-Verdifax-Key"]],
      json = if (is.null(json)) NULL else as.character(json),
      body = if (is.null(json)) NULL else jsonlite::fromJSON(json, simplifyVector = FALSE)
    )
    respond(req)
  }
  httr2::with_mocked_responses(mock, code)
  sent
}

test_that("verdifax_verify_run calls GET /runs/{id}/verify", {
  sent <- capture(
    result <- verdifax_verify_run(test_client(), 7),
    function(req) json_response("{\"ok\":true,\"verified\":true,\"recomputed_hash\":\"a\"}")
  )
  expect_equal(sent[[1]]$method, "GET")
  expect_equal(sent[[1]]$url$path, "/runs/7/verify")
  expect_equal(sent[[1]]$key, "k")
  expect_true(result$verified)
})

test_that("a large run id is written out in full", {
  sent <- capture(verdifax_get_run(test_client(), 1e5))
  expect_equal(sent[[1]]$url$path, "/runs/100000")
})

test_that("a bad run id is refused without a request", {
  for (bad in list(0, -1, 1.5, NA_real_, "7", c(1, 2))) {
    sent <- capture(expect_error(verdifax_verify_run(test_client(), bad), "run_id"))
    expect_length(sent, 0)
  }
})

test_that("verdifax_get_run returns the run", {
  sent <- capture(
    run <- verdifax_get_run(test_client(), 7),
    function(req) json_response("{\"ok\":true,\"id\":7,\"status\":\"ok\"}")
  )
  expect_equal(sent[[1]]$url$path, "/runs/7")
  expect_equal(run$id, 7)
})

test_that("a failed fetch stops with the HTTP status and the server's message", {
  respond <- function(req) json_response("{\"ok\":false,\"error\":\"run not found\"}", 404)
  capture(
    expect_error(verdifax_get_run(test_client(), 7), "run not found", class = "httr2_http_404"),
    respond
  )
})

test_that("verdifax_list_runs sends limit and offset", {
  sent <- capture(
    page <- verdifax_list_runs(test_client(), limit = 100000, offset = 4),
    function(req) json_response("{\"ok\":true,\"total\":9,\"runs\":[{\"id\":7}]}")
  )
  expect_equal(sent[[1]]$url$path, "/runs")
  expect_equal(sent[[1]]$url$query, list(limit = "100000", offset = "4"))
  expect_equal(page$total, 9)
  expect_equal(page$runs[[1]]$id, 7)
})

test_that("verdifax_list_runs with no arguments sends no query", {
  sent <- capture(verdifax_list_runs(test_client()))
  expect_equal(sent[[1]]$url$path, "/runs")
  expect_null(sent[[1]]$url$query)
})

test_that("verdifax_search_runs sends every filter", {
  sent <- capture(verdifax_search_runs(
    test_client(),
    manifest_hash = "ab",
    program_id = .program_id,
    route_id = "r 1",
    status = "ok",
    from = "2026-11-01T00:00:00+02:00",
    to = "2026-11-05T00:00:00Z",
    limit = 2,
    offset = 4
  ))
  expect_equal(sent[[1]]$method, "GET")
  expect_equal(sent[[1]]$url$path, "/runs/search")
  expect_equal(sent[[1]]$url$query, list(
    manifest_hash = "ab",
    program_id = .program_id,
    route_id = "r 1",
    status = "ok",
    from = "2026-11-01T00:00:00+02:00",
    to = "2026-11-05T00:00:00Z",
    limit = "2",
    offset = "4"
  ))
})

test_that("verdifax_export_runs sends the period and parses the body", {
  sent <- capture(
    out <- verdifax_export_runs(
      test_client(),
      from = "2026-11-01T00:00:00+02:00",
      to = "2026-11-05T00:00:00Z"
    ),
    function(req) json_response(
      "{\"ok\":true,\"total\":3,\"returned\":1,\"truncated\":true,\"by_status\":{\"ok\":1},\"runs\":[{\"run_id\":1}]}"
    )
  )
  expect_equal(sent[[1]]$method, "GET")
  expect_equal(sent[[1]]$url$path, "/runs/export")
  expect_equal(sent[[1]]$url$query, list(
    from = "2026-11-01T00:00:00+02:00",
    to = "2026-11-05T00:00:00Z",
    format = "json"
  ))
  expect_true(out$truncated)
  expect_equal(out$by_status$ok, 1)
  expect_equal(out$runs[[1]]$run_id, 1)
})

csv_response <- function(total = "1", truncated = "false") {
  headers <- list("Content-Type" = "text/csv; charset=utf-8")
  headers[["X-Verdifax-Total"]] <- total
  headers[["X-Verdifax-Truncated"]] <- truncated
  httr2::response(status_code = 200, headers = headers, body = charToRaw(.csv))
}

test_that("verdifax_export_runs_csv returns the CSV text unparsed with its counts", {
  sent <- capture(
    out <- verdifax_export_runs_csv(test_client(), from = "2026-11-01T00:00:00Z"),
    function(req) csv_response()
  )
  expect_equal(sent[[1]]$url$query, list(from = "2026-11-01T00:00:00Z", format = "csv"))
  expect_identical(out, list(csv = .csv, total = 1, truncated = FALSE))
})

test_that("verdifax_export_runs_csv reports a truncated export", {
  capture(
    out <- verdifax_export_runs_csv(test_client()),
    function(req) csv_response("12000", "true")
  )
  expect_equal(out$total, 12000)
  expect_true(out$truncated)
})

test_that("verdifax_export_runs_csv refuses a response without its counts", {
  responses <- list(
    csv_response(NULL, NULL),
    csv_response("1", NULL),
    csv_response(NULL, "false"),
    csv_response("x", "false"),
    csv_response("1", "maybe")
  )
  for (response in responses) {
    capture(
      expect_error(verdifax_export_runs_csv(test_client()), "may be cut off"),
      function(req) response
    )
  }
})

test_that("a refused export time stops with the server's message", {
  respond <- function(req) {
    json_response("{\"ok\":false,\"error\":\"from must be an RFC 3339 time\"}", 400)
  }
  capture(
    expect_error(
      verdifax_export_runs_csv(test_client(), from = "yesterday"),
      "RFC 3339",
      class = "httr2_http_400"
    ),
    respond
  )
})

test_that("verdifax_execute_batch posts runs and returns failed rows", {
  respond <- function(req) json_response(paste0(
    "{\"ok\":true,\"total\":2,\"successful\":1,\"failed\":1,\"results\":[",
    "{\"index\":0,\"ok\":true,\"run_id\":1},",
    "{\"index\":1,\"ok\":false,\"error\":\"route_id required\"}]}"
  ))
  bad <- .row
  bad$route_id <- ""
  sent <- capture(out <- verdifax_execute_batch(test_client(), list(.row, bad)), respond)
  expect_length(sent, 1)
  expect_equal(sent[[1]]$method, "POST")
  expect_equal(sent[[1]]$url$path, "/execute/batch")
  expect_named(sent[[1]]$body, "runs")
  expect_length(sent[[1]]$body$runs, 2)
  expect_equal(sent[[1]]$body$runs[[1]]$payload_text, "hello")
  expect_null(sent[[1]]$body$runs[[1]]$request_signature)
  expect_equal(sent[[1]]$body$runs[[2]]$route_id, "")
  expect_equal(out$failed, 1)
  expect_false(out$results[[2]]$ok)
  expect_equal(out$results[[2]]$error, "route_id required")
})

test_that("one row is still sent as a JSON array", {
  sent <- capture(verdifax_execute_batch(test_client(), list(.row)))
  expect_match(sent[[1]]$json, "^\\{\"runs\":\\[\\{")
})

test_that("a binary payload and the optional fields reach the row", {
  row <- .row
  row$payload <- as.raw(c(0xff, 0xfe))
  row$ai_output_text <- "out"
  row$reproducibility_context <- list(runtime_name = "R", random_seeds = "rng=1")
  row$attested_context <- list(actor_role = "reviewer")
  sent <- capture(verdifax_execute_batch(test_client(), list(row)))
  body <- sent[[1]]$body$runs[[1]]
  expect_equal(body[["payload"]], "//4=")
  expect_equal(body$ai_output_text, "out")
  expect_equal(body$reproducibility_context$random_seeds, list("rng=1"))
  expect_equal(body$attested_context$actor_role, "reviewer")
})

test_that("a row with missing fields goes to the server without NULL fields", {
  sent <- capture(verdifax_execute_batch(test_client(), list(list(payload = "x"))))
  expect_equal(sent[[1]]$json, "{\"runs\":[{\"payload_text\":\"x\"}]}")
})

test_that("a batch is refused above 1,000 rows without a request", {
  sent <- capture({
    expect_error(
      verdifax_execute_batch(test_client(), rep(list(.row), 1001)),
      "at most 1000 runs (got 1001)",
      fixed = TRUE
    )
    expect_error(verdifax_execute_batch(test_client(), list()), "at least one run")
  })
  expect_length(sent, 0)
  sent <- capture(verdifax_execute_batch(test_client(), rep(list(.row), 1000)))
  expect_length(sent, 1)
  expect_length(sent[[1]]$body$runs, 1000)
})

test_that("a batch must be an unnamed list of named rows", {
  sent <- capture({
    expect_error(verdifax_execute_batch(test_client(), .row), "unnamed list of rows")
    expect_error(verdifax_execute_batch(test_client(), list("hello")), "named list")
  })
  expect_length(sent, 0)
})

test_that("a batch and a determinism check are not retried", {
  calls <- list(
    function() verdifax_execute_batch(test_client(), list(.row)),
    function() verdifax_verify_determinism(
      client = test_client(),
      payload = "hello",
      program_id = .program_id,
      route_id = "r",
      registry_record_hash = .registry_record_hash
    )
  )
  for (call in calls) {
    sent <- capture(
      expect_error(call(), class = "httr2_http_503"),
      function(req) json_response("{\"error\":\"busy\"}", 503)
    )
    expect_length(sent, 1)
  }
})

test_that("a signed batch gives each row its own signature and nonce", {
  need_sodium()
  rows <- list(.row, .row, utils::modifyList(.row, list(payload = "other")))
  sent <- capture(verdifax_execute_batch(test_client(as.raw(rep(1L, 32))), rows))
  body <- sent[[1]]$body$runs
  expect_length(body, 3)
  public_key <- jsonlite::base64_dec("iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=")
  hex <- function(text) sodium::bin2hex(sodium::sha256(charToRaw(text)))
  for (row in body) {
    expect_setequal(names(row), c("signed_request", "request_signature"))
    signature <- row$request_signature
    expect_identical(signature$version, "2")
    expect_match(signature$nonce, "^[0-9a-f]{32}$")
    request <- jsonlite::fromJSON(row$signed_request, simplifyVector = FALSE)
    fields <- lapply(list(
      "verdifax.request.v2",
      hex(row$signed_request),
      hex(request$payload_text),
      request$program_id,
      request$route_id,
      request$registry_record_hash,
      "",
      "verdifax.job.v1",
      "", "", "", "",
      "false",
      signature$signed_at,
      signature$nonce
    ), charToRaw)
    signed <- Reduce(function(a, b) c(a, as.raw(0), b), fields)
    expect_true(sodium::sig_verify(signed, jsonlite::base64_dec(signature$signature), public_key))
  }
  nonces <- vapply(body, function(row) row$request_signature$nonce, character(1))
  signatures <- vapply(body, function(row) row$request_signature$signature, character(1))
  expect_length(unique(nonces), 3)
  expect_length(unique(signatures), 3)
})

test_that("a signed batch sends an incomplete row for the server to report", {
  need_sodium()
  sent <- capture(
    verdifax_execute_batch(test_client(as.raw(rep(1L, 32))), list(list(payload = "x")))
  )
  row <- sent[[1]]$body$runs[[1]]
  expect_false(is.null(row$request_signature))
  expect_null(jsonlite::fromJSON(row$signed_request, simplifyVector = FALSE)$program_id)
})

test_that("each batch result holds its row's signed text, by position", {
  need_sodium()
  rows <- list(.row, utils::modifyList(.row, list(payload = "other")))
  # The server leaves index 0 on a row it could not read.
  reply <- paste0(
    "{\"ok\":true,\"total\":2,\"results\":[",
    "{\"index\":0,\"ok\":true,\"record_hash\":\"a\"},",
    "{\"index\":0,\"ok\":false,\"error\":\"x\"}]}"
  )
  sent <- capture(
    result <- verdifax_execute_batch(test_client(as.raw(rep(1L, 32))), rows),
    function(req) json_response(reply)
  )
  runs <- sent[[1]]$body$runs
  expect_identical(result$results[[1]]$signed_request, runs[[1]]$signed_request)
  expect_identical(result$results[[2]]$signed_request, runs[[2]]$signed_request)
  expect_equal(result$results[[1]]$record_hash, "a")
})

test_that("an unsigned batch result has no signed_request", {
  capture(
    result <- verdifax_execute_batch(test_client(), list(.row)),
    function(req) json_response("{\"ok\":true,\"results\":[{\"index\":0,\"ok\":true}]}")
  )
  expect_null(result$results[[1]]$signed_request)
})

test_that("a batch the server refuses stops with its message", {
  capture(
    expect_error(
      verdifax_execute_batch(test_client(), list(.row)),
      "runs array is empty",
      class = "httr2_http_400"
    ),
    function(req) json_response("{\"ok\":false,\"error\":\"runs array is empty\"}", 400)
  )
})

test_that("verdifax_verify_determinism calls its endpoint with the request", {
  sent <- capture(
    out <- verdifax_verify_determinism(
      client = test_client(),
      payload = "hello",
      program_id = .program_id,
      route_id = "r",
      registry_record_hash = .registry_record_hash
    ),
    function(req) json_response("{\"ok\":true,\"deterministic\":true}")
  )
  expect_equal(sent[[1]]$method, "POST")
  expect_equal(sent[[1]]$url$path, "/execute/verify-determinism")
  expect_equal(sent[[1]]$body$payload_text, "hello")
  expect_true(out$deterministic)
})

test_that("the batch limit is public", {
  expect_equal(verdifax_max_batch_rows(), 1000L)
})

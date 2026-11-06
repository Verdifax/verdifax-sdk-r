# Job blocks and the job helper. Requests are captured by a mock, so nothing
# reaches the network.

.program_id <- strrep("1", 64)
.registry_record_hash <- strrep("2", 64)
.seed <- as.raw(rep(1L, 32))
.public_key <- "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w="
.hash_a <- strrep("a", 64)
.hash_b <- strrep("b", 64)
.hash_c <- strrep("c", 64)
.hash_d <- strrep("d", 64)

need_sodium <- function() {
  if (!nzchar(Sys.getenv("CI"))) {
    testthat::skip_if_not_installed("sodium")
  }
}

unsigned_client <- function() {
  verdifax_client(base_url = "http://mock.invalid", api_key = "k")
}

signed_client <- function() {
  verdifax_client(base_url = "http://mock.invalid", api_key = "k", signing_key = .seed)
}

json_response <- function(text, status = 200) {
  httr2::response(
    status_code = status,
    headers = "Content-Type: application/json",
    body = charToRaw(text)
  )
}

record <- function(hash) {
  json_response(sprintf("{\"ok\":true,\"run_id\":1,\"record_hash\":\"%s\"}", hash))
}

refused <- function(hash, status = 422) {
  json_response(sprintf(
    "{\"ok\":false,\"run_id\":2,\"record_hash\":\"%s\",\"error\":\"policy denied\"}", hash
  ), status)
}

# Runs `code`, answers the requests with `replies` in turn, and returns what
# was sent, decoded from the JSON the request would put on the wire.
capture <- function(code, replies = list(record(.hash_a))) {
  sent <- list()
  mock <- function(req) {
    body <- httr2::req_get_body(req)
    json <- if (is.null(body)) NULL else jsonlite::toJSON(body, auto_unbox = TRUE, digits = 22, null = "null")
    sent[[length(sent) + 1]] <<- list(
      url = httr2::url_parse(httr2::req_get_url(req)),
      json = if (is.null(json)) NULL else as.character(json),
      body = if (is.null(json)) NULL else jsonlite::fromJSON(json, simplifyVector = FALSE)
    )
    replies[[length(sent)]]
  }
  httr2::with_mocked_responses(mock, code)
  sent
}

run_step <- function(job, step_id, ...) {
  verdifax_job_step(
    job, step_id, ...,
    payload = paste("payload", step_id),
    program_id = .program_id,
    route_id = "route",
    registry_record_hash = .registry_record_hash
  )
}

run_attest <- function(client, job) {
  verdifax_attest(
    client = client,
    payload = "hello",
    program_id = .program_id,
    route_id = "route",
    registry_record_hash = .registry_record_hash,
    job = job
  )
}

# Rebuilds the signed bytes as the server does, independently of the SDK.
job_signature_verifies <- function(body, job_id, step_id, previous, external, final) {
  request <- jsonlite::fromJSON(body$signed_request, simplifyVector = FALSE)
  hex <- function(text) sodium::bin2hex(sodium::sha256(charToRaw(text)))
  fields <- lapply(list(
    "verdifax.request.v2",
    hex(body$signed_request),
    hex(request$payload_text),
    request$program_id,
    request$route_id,
    request$registry_record_hash,
    "",
    "verdifax.job.v1",
    job_id,
    step_id,
    previous,
    external,
    final,
    body$request_signature$signed_at,
    body$request_signature$nonce
  ), charToRaw)
  signed <- Reduce(function(a, b) c(a, as.raw(0), b), fields)
  sodium::sig_verify(
    signed,
    jsonlite::base64_dec(body$request_signature$signature),
    jsonlite::base64_dec(.public_key)
  )
}

.bad_names <- list(
  "", strrep("a", 129), "has space", "a/b", "café", "a\n", "\na", NA_character_,
  c("a", "b"), 5L, character(0), NULL
)

test_that("an unsigned attest sends plain JSON with the job block", {
  sent <- capture(result <- run_attest(unsigned_client(), list(
    job_id = "loan-1",
    step_id = "decide",
    previous_record_hashes = c(.hash_b, .hash_a, .hash_b),
    external_previous = .hash_c,
    final = TRUE
  )))
  body <- sent[[1]]$body
  expect_equal(body$payload_text, "hello")
  expect_null(body$signed_request)
  expect_null(body$request_signature)
  expect_equal(body$job, list(
    job_id = "loan-1",
    step_id = "decide",
    previous_record_hashes = list(.hash_a, .hash_b),
    external_previous = list(.hash_c),
    final = TRUE
  ))
  expect_equal(result$record_hash, .hash_a)
})

test_that("a call with no job sends no job block", {
  sent <- capture(run_attest(unsigned_client(), NULL))
  expect_null(sent[[1]]$body$job)
})

test_that("empty lists and a false final are left out", {
  sent <- capture(run_attest(unsigned_client(), list(
    job_id = "j", step_id = "s", previous_record_hashes = character(0),
    external_previous = list(), final = FALSE
  )))
  expect_equal(sent[[1]]$body$job, list(job_id = "j", step_id = "s"))
})

test_that("one hash is still sent as a JSON array", {
  sent <- capture(run_attest(unsigned_client(), list(
    job_id = "j", step_id = "s", previous_record_hashes = .hash_a
  )))
  expect_match(sent[[1]]$json, sprintf("\"previous_record_hashes\":[\"%s\"]", .hash_a), fixed = TRUE)
})

test_that("job hashes sort in byte order in any locale", {
  block <- verdifax:::.job_block(list(
    job_id = "j", step_id = "s", previous_record_hashes = c("b", "B", "a", "1", "a")
  ))
  expect_equal(block$previous_record_hashes, list("1", "B", "a", "b"))
})

test_that("a named vector of hashes is still sent as an array", {
  block <- verdifax:::.job_block(list(
    job_id = "j", step_id = "s", previous_record_hashes = c(first = .hash_a)
  ))
  expect_null(names(block$previous_record_hashes))
  expect_equal(block$previous_record_hashes, list(.hash_a))
})

test_that("hash lists that are not strings are refused without a request", {
  for (bad in list(5, TRUE, list(5), list(.hash_a, 5), list(.hash_a, NULL),
                   list(c(.hash_a, .hash_b)), list(list(.hash_a)), list(NA_character_),
                   factor(.hash_a))) {
    sent <- capture({
      expect_error(
        run_attest(unsigned_client(), list(job_id = "j", step_id = "s", previous_record_hashes = bad)),
        "previous_record_hashes"
      )
      expect_error(
        run_attest(unsigned_client(), list(job_id = "j", step_id = "s", external_previous = bad)),
        "external_previous"
      )
    })
    expect_length(sent, 0)
  }
})

test_that("a field named twice is refused, so no link is dropped", {
  sent <- capture(expect_error(
    run_attest(unsigned_client(), list(
      job_id = "j", step_id = "s",
      previous_record_hashes = .hash_a, previous_record_hashes = .hash_b
    )),
    "twice"
  ))
  expect_length(sent, 0)
})

test_that("a non-boolean final is refused on a step", {
  job <- verdifax_job(unsigned_client(), "loan-1")
  for (bad in list("yes", 1, NA, c(TRUE, FALSE), logical(0))) {
    sent <- capture(expect_error(run_step(job, "one", final = bad), "final"))
    expect_length(sent, 0)
  }
  expect_length(job$record_hashes, 0)
})

test_that("a misspelled step argument is refused without a request", {
  job <- verdifax_job(unsigned_client(), "loan-1")
  sent <- capture({
    run_step(job, "one")
    expect_error(run_step(job, "two", afer = "one"), "unknown argument: afer")
    expect_error(run_step(job, "two", external_previus = .hash_a), "external_previus")
    expect_error(run_step(job, "two", finl = TRUE), "finl")
    expect_error(run_step(job, "two", client = unsigned_client()), "unknown argument: client")
  })
  expect_length(sent, 1)
  expect_equal(job$record_hashes, c(one = .hash_a))
})

test_that("a shortened attest argument is refused, not partially matched", {
  job <- verdifax_job(unsigned_client(), "loan-1")
  sent <- capture(expect_error(
    verdifax_job_step(
      job, "one",
      pay = "hello",
      program_id = .program_id,
      route_id = "route",
      registry_record_hash = .registry_record_hash
    ),
    "unknown argument: pay"
  ))
  expect_length(sent, 0)
})

test_that("a job argument is refused on a step without a request", {
  job <- verdifax_job(unsigned_client(), "loan-1")
  link <- list(job_id = "other", step_id = "s")
  sent <- capture({
    expect_error(verdifax_job_step(job, "one", job = link), "verdifax_job")
    expect_error(verdifax_job_step(job = job, step_id = "one", jo = link), "unknown argument: jo")
    expect_error(verdifax_job_step(job = job, step_id = "one", job = link), "matched by multiple")
  })
  expect_length(sent, 0)
  expect_length(job$record_hashes, 0)
})

test_that("a step can pass attest's arguments by position", {
  job <- verdifax_job(unsigned_client(), "loan-1")
  sent <- capture(verdifax_job_step(job, "one", "hello", .program_id, "route", .registry_record_hash))
  expect_equal(sent[[1]]$body$payload_text, "hello")
  expect_equal(sent[[1]]$body$job, list(job_id = "loan-1", step_id = "one"))
})

test_that("a list of hashes is accepted like a vector", {
  block <- verdifax:::.job_block(list(
    job_id = "j", step_id = "s", previous_record_hashes = list(.hash_b, .hash_a)
  ))
  expect_equal(block$previous_record_hashes, list(.hash_a, .hash_b))
})

test_that("invalid job names are refused without a request", {
  for (bad in .bad_names) {
    sent <- capture({
      expect_error(run_attest(unsigned_client(), list(job_id = bad, step_id = "s")), "job_id")
      expect_error(run_attest(unsigned_client(), list(job_id = "j", step_id = bad)), "step_id")
      expect_error(verdifax_job(unsigned_client(), bad), "job_id")
      expect_error(run_step(verdifax_job(unsigned_client(), "j"), bad), "step_id")
    })
    expect_length(sent, 0)
  }
})

test_that("every allowed name character is accepted", {
  expect_true(verdifax:::.check_job_name("aZ09._:-", "job_id"))
  expect_true(verdifax:::.check_job_name(strrep("a", 128), "job_id"))
})

test_that("a malformed job block is refused without a request", {
  sent <- capture({
    expect_error(run_attest(unsigned_client(), "loan-1"), "named list")
    expect_error(
      run_attest(unsigned_client(), list(job_id = "j", step_id = "s", previous_hashes = .hash_a)),
      "unknown field"
    )
    expect_error(
      run_attest(unsigned_client(), list(job_id = "j", step_id = "s", final = "yes")),
      "final"
    )
    expect_error(
      run_attest(unsigned_client(), list(job_id = "j", step_id = "s", final = NA)),
      "final"
    )
    expect_error(
      run_attest(unsigned_client(), list(job_id = "j", step_id = "s", external_previous = 5)),
      "external_previous"
    )
    expect_error(
      run_attest(unsigned_client(), list(
        job_id = "j", step_id = "s", previous_record_hashes = c(.hash_a, NA)
      )),
      "previous_record_hashes"
    )
  })
  expect_length(sent, 0)
})

test_that("verdifax_execute accepts a job", {
  sent <- capture(verdifax_execute(
    unsigned_client(),
    payload = "hello",
    program_id = .program_id,
    route_id = "route",
    registry_record_hash = .registry_record_hash,
    job = list(job_id = "j", step_id = "s")
  ))
  expect_equal(sent[[1]]$body$job, list(job_id = "j", step_id = "s"))
})

test_that("a batch row accepts a job", {
  row <- list(
    payload = "hello", program_id = .program_id, route_id = "route",
    registry_record_hash = .registry_record_hash,
    job = list(job_id = "j", step_id = "s", previous_record_hashes = c(.hash_b, .hash_a))
  )
  sent <- capture(
    result <- verdifax_execute_batch(unsigned_client(), list(row)),
    list(json_response("{\"ok\":true,\"results\":[{\"index\":0,\"ok\":true,\"record_hash\":\"h\"}]}"))
  )
  expect_equal(sent[[1]]$body$runs[[1]]$job$previous_record_hashes, list(.hash_a, .hash_b))
  expect_equal(result$results[[1]]$record_hash, "h")
})

test_that("a signed batch row signs its job", {
  need_sodium()
  row <- list(
    payload = "hello", program_id = .program_id, route_id = "route",
    registry_record_hash = .registry_record_hash,
    job = list(job_id = "j", step_id = "s", previous_record_hashes = .hash_a, final = TRUE)
  )
  sent <- capture(
    verdifax_execute_batch(signed_client(), list(row)),
    list(json_response("{\"ok\":true,\"results\":[{\"index\":0,\"ok\":true}]}"))
  )
  sent_row <- sent[[1]]$body$runs[[1]]
  expect_setequal(names(sent_row), c("signed_request", "request_signature"))
  expect_true(job_signature_verifies(sent_row, "j", "s", .hash_a, "", "true"))
})

test_that("a batch row with a bad job name is refused without a request", {
  row <- list(payload = "x", job = list(job_id = "not valid", step_id = "s"))
  sent <- capture(expect_error(verdifax_execute_batch(unsigned_client(), list(row)), "job_id"))
  expect_length(sent, 0)
})

test_that("a signed attest signs the sorted job fields", {
  need_sodium()
  sent <- capture(run_attest(signed_client(), list(
    job_id = "loan-1",
    step_id = "decide",
    previous_record_hashes = c(.hash_b, .hash_a),
    external_previous = c(.hash_d, .hash_c),
    final = TRUE
  )))
  expect_true(job_signature_verifies(
    sent[[1]]$body, "loan-1", "decide",
    paste(.hash_a, .hash_b, sep = ","), paste(.hash_c, .hash_d, sep = ","), "true"
  ))
})

test_that("verdifax_job starts empty and verdifax_job_step's first step follows nothing", {
  job <- verdifax_job(unsigned_client(), "loan-1")
  expect_s3_class(job, "verdifax_job")
  expect_length(job$record_hashes, 0)
  sent <- capture(result <- run_step(job, "intake"))
  expect_match(sent[[1]]$url$path, "/execute$")
  expect_equal(sent[[1]]$body$job, list(job_id = "loan-1", step_id = "intake"))
  expect_equal(result$record_hash, .hash_a)
  expect_equal(job$record_hashes, c(intake = .hash_a))
})

test_that("a step follows the step before it by default", {
  job <- verdifax_job(unsigned_client(), "loan-1")
  sent <- capture({
    run_step(job, "one")
    run_step(job, "two")
    run_step(job, "three")
  }, list(record(.hash_a), record(.hash_b), record(.hash_c)))
  expect_equal(sent[[2]]$body$job$previous_record_hashes, list(.hash_a))
  expect_equal(sent[[3]]$body$job$previous_record_hashes, list(.hash_b))
})

test_that("a branch and a join send the sorted hashes of the named steps", {
  job <- verdifax_job(unsigned_client(), "loan-1")
  sent <- capture({
    run_step(job, "start")
    run_step(job, "left", after = "start")
    run_step(job, "right", after = list("start"))
    run_step(job, "join", after = c("right", "left"), final = TRUE)
  }, list(record(.hash_a), record(.hash_d), record(.hash_b), record(.hash_c)))
  expect_equal(sent[[2]]$body$job$previous_record_hashes, list(.hash_a))
  expect_equal(sent[[3]]$body$job$previous_record_hashes, list(.hash_a))
  expect_equal(sent[[4]]$body$job$previous_record_hashes, list(.hash_b, .hash_d))
  expect_true(sent[[4]]$body$job$final)
  expect_null(sent[[3]]$body$job$final)
  expect_equal(
    job$record_hashes,
    c(start = .hash_a, left = .hash_d, right = .hash_b, join = .hash_c)
  )
})

test_that("an empty after starts another root step", {
  job <- verdifax_job(unsigned_client(), "loan-1")
  sent <- capture({
    run_step(job, "one")
    run_step(job, "two", after = character(0))
    run_step(job, "three", after = list())
    run_step(job, "four")
  }, list(record(.hash_a), record(.hash_b), record(.hash_c), record(.hash_d)))
  expect_null(sent[[2]]$body$job$previous_record_hashes)
  expect_null(sent[[3]]$body$job$previous_record_hashes)
  expect_equal(sent[[4]]$body$job$previous_record_hashes, list(.hash_c))
})

test_that("external_previous reaches the job block", {
  job <- verdifax_job(unsigned_client(), "loan-1")
  sent <- capture(run_step(job, "one", external_previous = c(.hash_d, .hash_c)))
  expect_equal(sent[[1]]$body$job$external_previous, list(.hash_c, .hash_d))
})

test_that("everything attest takes reaches a step", {
  job <- verdifax_job(unsigned_client(), "loan-1")
  sent <- capture(run_step(
    job, "one",
    ai_output_text = "the answer",
    causal_graph = list(reason = "because")
  ))
  expect_equal(sent[[1]]$body$ai_output_text, "the answer")
  expect_equal(sent[[1]]$body$causal_graph, list(reason = "because"))
})

test_that("a refused step is recorded and the same error is raised", {
  job <- verdifax_job(unsigned_client(), "loan-1")
  capture(direct <- tryCatch(
    run_attest(unsigned_client(), list(job_id = "j", step_id = "s")),
    error = function(e) e
  ), list(refused(.hash_b)))
  sent <- capture({
    run_step(job, "one")
    err <- tryCatch(run_step(job, "two"), error = function(e) e)
    run_step(job, "three")
    run_step(job, "four", after = c("two", "one"))
  }, list(record(.hash_a), refused(.hash_b), record(.hash_c), record(.hash_d)))
  expect_s3_class(err, "httr2_http_422")
  expect_identical(class(err), class(direct))
  expect_identical(conditionMessage(err), conditionMessage(direct))
  expect_equal(err$record_hash, .hash_b)
  expect_equal(
    job$record_hashes,
    c(one = .hash_a, two = .hash_b, three = .hash_c, four = .hash_d)
  )
  # The step after a refused one follows it by default.
  expect_equal(sent[[3]]$body$job$previous_record_hashes, list(.hash_b))
  expect_equal(sent[[4]]$body$job$previous_record_hashes, list(.hash_a, .hash_b))
})

test_that("attest keeps its error and adds the record hash", {
  capture(err <- tryCatch(run_attest(unsigned_client(), NULL), error = function(e) e), list(refused(.hash_b)))
  expect_s3_class(err, "httr2_http_422")
  expect_equal(err$record_hash, .hash_b)
  expect_null(err$signed_request)
  expect_equal(httr2::resp_status(err$resp), 422)
})

test_that("a signed refusal holds the text that was signed", {
  need_sodium()
  sent <- capture(
    err <- tryCatch(run_attest(signed_client(), NULL), error = function(e) e),
    list(refused(.hash_b))
  )
  expect_identical(err$signed_request, sent[[1]]$body$signed_request)
})

test_that("a refused determinism check holds the text that was signed", {
  need_sodium()
  sent <- capture(
    err <- tryCatch(verdifax_verify_determinism(
      client = signed_client(),
      payload = "hello",
      program_id = .program_id,
      route_id = "route",
      registry_record_hash = .registry_record_hash
    ), error = function(e) e),
    list(refused(.hash_b))
  )
  expect_s3_class(err, "httr2_http_422")
  expect_identical(err$signed_request, sent[[1]]$body$signed_request)
})

test_that("verdifax_execute errors still carry both fields", {
  need_sodium()
  sent <- capture(
    err <- tryCatch(verdifax_execute(
      signed_client(),
      payload = "hello",
      program_id = .program_id,
      route_id = "route",
      registry_record_hash = .registry_record_hash,
      job = list(job_id = "j", step_id = "s")
    ), error = function(e) e),
    list(refused(.hash_b))
  )
  expect_s3_class(err, "httr2_http_422")
  expect_equal(err$record_hash, .hash_b)
  expect_identical(err$signed_request, sent[[1]]$body$signed_request)
  expect_false(grepl(err$signed_request, conditionMessage(err), fixed = TRUE))
})

test_that("verdifax_execute errors carry the record hash when unsigned", {
  capture(
    err <- tryCatch(verdifax_execute(
      unsigned_client(),
      payload = "hello",
      program_id = .program_id,
      route_id = "route",
      registry_record_hash = .registry_record_hash
    ), error = function(e) e),
    list(refused(.hash_b))
  )
  expect_equal(err$record_hash, .hash_b)
  expect_null(err$signed_request)
})

.providers <- list(verdifax_attest_claude_response, verdifax_attest_openai_response)

run_provider <- function(helper, client, job = NULL) {
  helper(
    client, "the prompt", "the response", .program_id, "route", .registry_record_hash,
    job = job
  )
}

test_that("provider helpers send the job block", {
  for (helper in .providers) {
    sent <- capture(result <- run_provider(helper, unsigned_client(), list(
      job_id = "j", step_id = "s", previous_record_hashes = c(.hash_b, .hash_a), final = TRUE
    )))
    expect_equal(sent[[1]]$body$job, list(
      job_id = "j", step_id = "s", previous_record_hashes = list(.hash_a, .hash_b), final = TRUE
    ))
    expect_equal(result$record_hash, .hash_a)
    expect_null(result$signed_request)
  }
})

test_that("provider helpers send no job block by default", {
  for (helper in .providers) {
    sent <- capture(run_provider(helper, unsigned_client()))
    expect_null(sent[[1]]$body$job)
  }
})

test_that("provider helpers keep govern in its old position", {
  sent <- capture(verdifax_attest_claude_response(
    unsigned_client(), "the prompt", "the response", .program_id, "route",
    .registry_record_hash, TRUE
  ))
  expect_equal(sent[[1]]$body$ai_output_text, "the response")
})

test_that("provider helpers refuse a bad job without a request", {
  for (helper in .providers) {
    sent <- capture(expect_error(
      run_provider(helper, unsigned_client(), list(job_id = "not valid", step_id = "s")),
      "job_id"
    ))
    expect_length(sent, 0)
  }
})

test_that("signed provider helpers return record_hash and signed_request", {
  need_sodium()
  for (helper in .providers) {
    sent <- capture(result <- run_provider(
      helper, signed_client(), list(job_id = "j", step_id = "s", final = TRUE)
    ))
    body <- sent[[1]]$body
    expect_setequal(names(body), c("signed_request", "request_signature"))
    expect_true(job_signature_verifies(body, "j", "s", "", "", "true"))
    expect_equal(result$record_hash, .hash_a)
    expect_identical(result$signed_request, body$signed_request)
  }
})

test_that("provider helper errors carry both fields", {
  need_sodium()
  for (helper in .providers) {
    sent <- capture(
      err <- tryCatch(run_provider(helper, signed_client()), error = function(e) e),
      list(refused(.hash_b))
    )
    expect_s3_class(err, "httr2_http_422")
    expect_equal(err$record_hash, .hash_b)
    expect_identical(err$signed_request, sent[[1]]$body$signed_request)
  }
})

test_that("a job goes unsigned after its client clears the key", {
  need_sodium()
  client <- signed_client()
  job <- verdifax_job(client, "loan-1")
  sent <- capture({
    verdifax_clear_request_key(client)
    run_step(job, "one")
  }, list(json_response("{\"ok\":true}"), record(.hash_a)))
  expect_named(sent[[1]]$body, "change")
  expect_null(sent[[2]]$body$signed_request)
  expect_null(sent[[2]]$body$request_signature)
  expect_equal(sent[[2]]$body$payload_text, "payload one")
  expect_equal(job$record_hashes, c(one = .hash_a))
  expect_length(job$signed_requests, 0)
})

test_that("the job helper keeps the signed text of a refused step", {
  need_sodium()
  job <- verdifax_job(signed_client(), "loan-1")
  sent <- capture({
    run_step(job, "one")
    err <- tryCatch(run_step(job, "two"), error = function(e) e)
  }, list(record(.hash_a), refused(.hash_b)))
  expect_s3_class(err, "httr2_http_422")
  expect_identical(err$signed_request, sent[[2]]$body$signed_request)
  expect_identical(job$signed_requests[["one"]], sent[[1]]$body$signed_request)
  expect_identical(job$signed_requests[["two"]], sent[[2]]$body$signed_request)
  expect_equal(job$record_hashes, c(one = .hash_a, two = .hash_b))
})

test_that("the signed text stays out of the error's message", {
  need_sodium()
  job <- verdifax_job(signed_client(), "loan-1")
  sent <- capture(
    err <- tryCatch(run_step(job, "one"), error = function(e) e),
    list(refused(.hash_b))
  )
  text <- sent[[1]]$body$signed_request
  printed <- paste(capture.output(print(err)), collapse = "\n")
  for (shown in c(conditionMessage(err), format(err), printed)) {
    expect_false(grepl(text, shown, fixed = TRUE))
    expect_false(grepl("payload_text", shown, fixed = TRUE))
    expect_false(grepl("payload one", shown, fixed = TRUE))
  }
  expect_identical(err$signed_request, text)
  expect_identical(job$signed_requests[["one"]], text)
})

test_that("the job helper keeps no signed text for an unsigned step", {
  job <- verdifax_job(unsigned_client(), "loan-1")
  capture(expect_error(run_step(job, "one"), class = "httr2_http_422"), list(refused(.hash_b)))
  expect_equal(job$record_hashes, c(one = .hash_b))
  expect_length(job$signed_requests, 0)
})

test_that("a failure that left no record is not recorded", {
  job <- verdifax_job(unsigned_client(), "loan-1")
  conflict <- json_response("{\"ok\":false,\"error\":\"step already taken\"}", 409)
  plain <- httr2::response(status_code = 502, body = charToRaw("bad gateway"))
  sent <- capture({
    run_step(job, "one")
    expect_error(run_step(job, "two"), class = "httr2_http_409")
    expect_error(run_step(job, "three"), class = "httr2_http_502")
    run_step(job, "four")
  }, list(record(.hash_a), conflict, plain, record(.hash_d)))
  expect_equal(job$record_hashes, c(one = .hash_a, four = .hash_d))
  expect_equal(sent[[4]]$body$job$previous_record_hashes, list(.hash_a))
})

test_that("a timeout is not recorded and does not advance the default after", {
  job <- verdifax_job(unsigned_client(), "loan-1")
  calls <- 0L
  mock <- function(req) {
    calls <<- calls + 1L
    if (calls == 2L) {
      stop(structure(
        class = c("httr2_failure", "httr2_error", "error", "condition"),
        list(message = "Timeout was reached", call = NULL)
      ))
    }
    record(if (calls == 1L) .hash_a else .hash_c)
  }
  sent <- list()
  capturing <- function(req) {
    sent[[length(sent) + 1]] <<- jsonlite::fromJSON(
      jsonlite::toJSON(httr2::req_get_body(req), auto_unbox = TRUE),
      simplifyVector = FALSE
    )
    mock(req)
  }
  httr2::with_mocked_responses(capturing, {
    run_step(job, "one")
    expect_error(run_step(job, "two"), class = "httr2_failure")
    run_step(job, "three")
  })
  expect_equal(job$record_hashes, c(one = .hash_a, three = .hash_c))
  expect_equal(sent[[3]]$job$previous_record_hashes, list(.hash_a))
})

test_that("an unknown after is refused without a request", {
  job <- verdifax_job(unsigned_client(), "loan-1")
  sent <- capture({
    run_step(job, "one")
    expect_error(run_step(job, "two", after = "missing"), "not in this job: missing")
    expect_error(run_step(job, "two", after = c("one", "missing")), "missing")
    expect_error(run_step(job, "two", after = 1), "after")
  })
  expect_length(sent, 1)
  expect_equal(job$record_hashes, c(one = .hash_a))
})

test_that("a successful step falls back to manifest_hash", {
  job <- verdifax_job(unsigned_client(), "loan-1")
  sent <- capture({
    run_step(job, "one")
    run_step(job, "two")
  }, list(
    json_response(sprintf("{\"ok\":true,\"manifest_hash\":\"%s\"}", .hash_a)),
    record(.hash_b)
  ))
  expect_equal(job$record_hashes, c(one = .hash_a, two = .hash_b))
  expect_equal(sent[[2]]$body$job$previous_record_hashes, list(.hash_a))
})

test_that("the fallback finds the manifest hash where /execute puts it", {
  job <- verdifax_job(unsigned_client(), "loan-1")
  capture(run_step(job, "one"), list(
    json_response(sprintf("{\"ok\":true,\"manifest\":{\"ManifestHash\":\"%s\"}}", .hash_a))
  ))
  expect_equal(job$record_hashes, c(one = .hash_a))
})

test_that("a top-level manifest_hash wins over the manifest's own hash", {
  job <- verdifax_job(unsigned_client(), "loan-1")
  capture(run_step(job, "one"), list(json_response(sprintf(
    "{\"ok\":true,\"manifest_hash\":\"%s\",\"manifest\":{\"ManifestHash\":\"%s\"}}",
    .hash_a, .hash_b
  ))))
  expect_equal(job$record_hashes, c(one = .hash_a))
})

test_that("record_hash wins over manifest_hash", {
  job <- verdifax_job(unsigned_client(), "loan-1")
  capture(run_step(job, "one"), list(json_response(sprintf(
    "{\"ok\":true,\"record_hash\":\"%s\",\"manifest_hash\":\"%s\"}", .hash_a, .hash_b
  ))))
  expect_equal(job$record_hashes, c(one = .hash_a))
})

test_that("a step answered with neither hash stops instead of leaving a gap", {
  job <- verdifax_job(unsigned_client(), "loan-1")
  capture(
    expect_error(run_step(job, "one"), "no record_hash or manifest_hash"),
    list(json_response("{\"ok\":true}"))
  )
  expect_length(job$record_hashes, 0)
})

test_that("verdifax_job_step needs a job", {
  expect_error(verdifax_job_step(list(), "one"), "verdifax_job")
})

test_that("a signed step sends the signed shape and returns its text", {
  need_sodium()
  job <- verdifax_job(signed_client(), "loan-1")
  sent <- capture({
    run_step(job, "one")
    second <- run_step(job, "two", final = TRUE)
  }, list(record(.hash_a), record(.hash_b)))
  body <- sent[[2]]$body
  expect_setequal(names(body), c("signed_request", "request_signature"))
  expect_true(job_signature_verifies(body, "loan-1", "two", .hash_a, "", "true"))
  expect_identical(second$signed_request, body$signed_request)
})

test_that("a job keeps working after its client rotates its key", {
  need_sodium()
  client <- signed_client()
  job <- verdifax_job(client, "loan-1")
  new_key <- as.raw(rep(2L, 32))
  new_public <- verdifax_request_key_registration_body(new_key)$public_key
  sent <- capture({
    verdifax_rotate_request_key(client, new_key)
    run_step(job, "one")
  }, list(json_response("{\"ok\":true}"), record(.hash_a)))
  body <- sent[[2]]$body
  request <- verdifax:::.signed_text_preimage(
    body$signed_request, body$request_signature$signed_at, body$request_signature$nonce
  )
  expect_true(sodium::sig_verify(
    request,
    jsonlite::base64_dec(body$request_signature$signature),
    jsonlite::base64_dec(new_public)
  ))
})

test_that("verdifax_export_runs sends job_id and passes the new fields through", {
  reply <- json_response(
    "{\"ok\":true,\"runs\":[{\"run_id\":1,\"anchor_source\":\"public_log\",\"job_id\":\"loan-1\",\"step_id\":\"one\"}]}"
  )
  sent <- capture(out <- verdifax_export_runs(unsigned_client(), job_id = "loan-1"), list(reply))
  expect_equal(sent[[1]]$url$path, "/runs/export")
  expect_equal(sent[[1]]$url$query, list(job_id = "loan-1", format = "json"))
  expect_equal(out$runs[[1]]$anchor_source, "public_log")
  expect_equal(out$runs[[1]]$job_id, "loan-1")
  expect_equal(out$runs[[1]]$step_id, "one")
})

test_that("verdifax_export_runs leaves job_id out when unset", {
  sent <- capture(verdifax_export_runs(unsigned_client()))
  expect_equal(sent[[1]]$url$query, list(format = "json"))
})

test_that("verdifax_export_runs_csv sends job_id", {
  reply <- httr2::response(
    status_code = 200,
    headers = list("X-Verdifax-Total" = "1", "X-Verdifax-Truncated" = "false"),
    body = charToRaw("run_id\n1\n")
  )
  sent <- capture(out <- verdifax_export_runs_csv(unsigned_client(), job_id = "loan-1"), list(reply))
  expect_equal(sent[[1]]$url$query, list(job_id = "loan-1", format = "csv"))
  expect_equal(out$total, 1)
})

test_that("an export refuses a bad job_id without a request", {
  sent <- capture({
    expect_error(verdifax_export_runs(unsigned_client(), job_id = "not valid"), "job_id")
    expect_error(verdifax_export_runs_csv(unsigned_client(), job_id = "not valid"), "job_id")
  })
  expect_length(sent, 0)
})

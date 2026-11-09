# The account owner publishes the account's records: the two functions post
# to the owner routes with no body and return the server's answer as parsed,
# the sealed publication included.

owner_client <- function() {
  verdifax_client(base_url = "http://mock.invalid", api_key = "owner")
}

json_response <- function(text, status = 200) {
  httr2::response(
    status_code = status,
    headers = list(`Content-Type` = "application/json"),
    body = charToRaw(text)
  )
}

.answer <- paste0(
  '{"ok":true,"run_id":41,"public":true,"public_bundle_url":"https://api.verdifax.com/public/runs/tok/bundle.json",',
  '"verify_url":"https://verdifax.com/verify/?pt=tok","publication":{"format":"verdifax.run-publication.v1",',
  '"action":"run.published","run_id":41,"record_hash":"', strrep("a", 64), '","job_id":"loan-1","step_id":"verdict",',
  '"changed_at":"2026-11-08T20:00:00Z","signal":{"signal_account":"account-7","signal_sequence":9,',
  '"signal_previous_hash":"', strrep("b", 64), '"},"publication_hash":"', strrep("c", 64), '","later_field":"kept"}}'
)

capture <- function(code) {
  sent <- list()
  mock <- function(req) {
    url <- httr2::url_parse(httr2::req_get_url(req))
    sent[[length(sent) + 1]] <<- list(
      method = httr2::req_get_method(req), path = url$path,
      key = httr2::req_get_headers(req, "reveal")[["X-Verdifax-Key"]],
      body = httr2::req_get_body(req)
    )
    json_response(.answer)
  }
  httr2::with_mocked_responses(mock, code)
  sent
}

test_that("publish_run and unpublish_run post to the owner routes and return the answer as sent", {
  sent <- capture({
    published <- verdifax_publish_run(owner_client(), 41)
    withdrawn <- verdifax_unpublish_run(owner_client(), 41)
    expect_true(published$ok)
    expect_equal(published$run_id, 41)
    expect_true(published$public)
    expect_equal(published$publication$action, "run.published")
    expect_equal(published$publication$job_id, "loan-1")
    expect_equal(published$publication$signal$signal_sequence, 9)
    expect_equal(published$publication$later_field, "kept")
    expect_equal(withdrawn$run_id, 41)
  })
  expect_length(sent, 2)
  expect_equal(sent[[1]]$method, "POST")
  expect_equal(sent[[1]]$path, "/account/runs/41/publish")
  expect_equal(sent[[2]]$path, "/account/runs/41/unpublish")
  expect_equal(sent[[1]]$key, "owner")
  expect_null(sent[[1]]$body)
})

test_that("publish_run refuses a bad run id before sending", {
  sent <- capture({
    for (bad in list(0, -1, 1.5, "41", NA, NULL, c(1, 2))) {
      expect_error(verdifax_publish_run(owner_client(), bad))
      expect_error(verdifax_unpublish_run(owner_client(), bad))
    }
  })
  expect_length(sent, 0)
})

test_that("the publication kinds are signal kinds", {
  expect_true(all(c("run.published", "run.unpublished") %in% .SIGNAL_KINDS))
})


test_that("publishing a stopped run returns its receipt address and no bundle address (R156)", {
  stopped <- paste0(
    '{"ok":true,"run_id":42,"public":true,"public_receipt_url":"https://api.verdifax.com/public/runs/tok/receipt.json",',
    '"verify_url":"https://verdifax.com/verify/?pt=tok&record=receipt","publication":null}'
  )
  httr2::with_mocked_responses(function(req) json_response(stopped), {
    answer <- verdifax_publish_run(owner_client(), 42)
    expect_equal(answer$public_receipt_url, "https://api.verdifax.com/public/runs/tok/receipt.json")
    expect_null(answer$public_bundle_url)
  })
})

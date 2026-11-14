# Round 62: the owner adds and removes a webhook only with a record in the
# account's feed, signed by the owner key's request key over
# verdifax_webhook_value(): the SHA-256 of the address and the kinds, never
# the address. Requests are captured by a mock; nothing reaches the network.

webhook_capture <- function(code, respond = webhook_sealing_server()) {
  sent <- list()
  mock <- function(req) {
    body <- httr2::req_get_body(req)
    json <- if (is.null(body)) NULL else as.character(jsonlite::toJSON(body, auto_unbox = TRUE, digits = 22, null = "null"))
    sent[[length(sent) + 1]] <<- list(method = httr2::req_get_method(req), path = httr2::url_parse(httr2::req_get_url(req))$path,
                                      json = json, body = if (is.null(json)) NULL else jsonlite::fromJSON(json, simplifyVector = FALSE))
    respond(req)
  }
  httr2::with_mocked_responses(mock, code)
  sent
}

webhook_signature_verifies <- function(signature, change, subject) {
  fields <- lapply(list("verdifax.owner-change-signature.v1", "account-7", change, subject, signature$signed_at, signature$nonce),
                   function(text) charToRaw(enc2utf8(text)))
  signed <- Reduce(function(a, b) c(a, as.raw(0), b), fields)
  # sodium::sig_verify stops on a signature that does not verify.
  tryCatch(sodium::sig_verify(signed, jsonlite::base64_dec(signature$signature), jsonlite::base64_dec(.webhook_public_key)),
           error = function(e) FALSE)
}

test_that("verdifax_webhook_value matches the shared vector", {
  vector <- jsonlite::fromJSON(test_path("sdk-webhook-change-vector.json"), simplifyVector = FALSE)
  expect_equal(c(vector$changes$subscribe, vector$changes$delete), c("webhook.subscribed", "webhook.deleted"))
  for (case in vector$cases) {
    expect_equal(verdifax_webhook_value(case$url, unlist(case$types)), case$value, info = case$name)
    expect_equal(expected_webhook_value(case$url, case$types), case$value, info = case$name)
  }
})

test_that("create_webhook reads the account, signs the subscription and checks the record", {
  testthat::skip_if_not_installed("sodium")
  sent <- webhook_capture(result <- verdifax_create_webhook(webhook_owner_client(), .webhook_token_url, types = "run.refused"))
  expect_equal(vapply(sent, function(s) paste(s$method, s$path), ""), c("GET /account", "POST /account/webhooks"))
  expect_equal(names(sent[[2]]$body), c("url", "types", "owner_signature"))
  value <- expected_webhook_value(.webhook_token_url, "run.refused")
  expect_true(webhook_signature_verifies(sent[[2]]$body$owner_signature, "webhook.subscribed", value))
  expect_false(webhook_signature_verifies(sent[[2]]$body$owner_signature, "webhook.deleted", value))
  expect_equal(result$account_change$value, value)
  expect_false(grepl("s3cret", jsonlite::toJSON(result$account_change, auto_unbox = TRUE)))
})

test_that("webhook changes need the signing key and send nothing without it", {
  unsigned <- verdifax_client(base_url = "http://mock.invalid", api_key = "owner")
  sent <- webhook_capture({
    expect_error(verdifax_create_webhook(unsigned, .webhook_token_url), "must be signed by the owner key's request key")
    expect_error(verdifax_delete_webhook(unsigned, 3), "must be signed by the owner key's request key")
  })
  expect_length(sent, 0)
})

test_that("a record that does not carry what was sent stops the call", {
  for (field in list(list("action", "webhook.deleted"), list("value", paste0("sha256=", strrep("0", 64), " kinds=all")),
                     list("decided_by", "verdifax_admin"))) {
    tamper <- function(record) { record[[field[[1]]]] <- field[[2]]; record }
    webhook_capture(expect_error(
      verdifax_create_webhook(webhook_owner_client(), .webhook_token_url, account_id = "account-7"),
      "does not carry the action, value"
    ), webhook_sealing_server(tamper = tamper))
  }
})

test_that("delete_webhook reads the subscription and signs its value", {
  testthat::skip_if_not_installed("sodium")
  sent <- webhook_capture(result <- verdifax_delete_webhook(webhook_owner_client(), 3))
  expect_equal(vapply(sent, function(s) paste(s$method, s$path), ""),
               c("GET /account/webhooks", "GET /account", "DELETE /account/webhooks/3"))
  expect_equal(names(sent[[3]]$body), "owner_signature")
  expect_true(webhook_signature_verifies(sent[[3]]$body$owner_signature, "webhook.deleted",
                                         expected_webhook_value(.webhook_token_url, "run.refused")))
  expect_true(result$deleted)
})

test_that("delete_webhook of no such subscription sends no removal", {
  sent <- webhook_capture(expect_error(verdifax_delete_webhook(webhook_owner_client(), 4), "no webhook 4"))
  expect_false(any(vapply(sent, function(s) s$method == "DELETE", TRUE)))
})

# Round 62: a fake server for webhook changes, loaded before every test file.
# It answers each change with the record the server seals, carrying what was
# sent under the owner's public key; the value is written out here,
# independently of the SDK.

.webhook_seed <- as.raw(rep(1L, 32))
.webhook_public_key <- "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w="
.webhook_token_url <- "https://hooks.example.com/verdifax?token=s3cret"

# A signing client needs sodium: CI installs it, so there the tests always run;
# elsewhere they skip without it, as the suite's other signing tests do.
webhook_owner_client <- function() {
  if (!nzchar(Sys.getenv("CI"))) testthat::skip_if_not_installed("sodium")
  verdifax_client(base_url = "http://mock.invalid", api_key = "owner", signing_key = .webhook_seed)
}

expected_webhook_value <- function(url, types = NULL) {
  kinds <- if (length(types) == 0) "all" else paste(sort(unlist(types), method = "radix"), collapse = ",")
  paste0("sha256=", paste(as.character(openssl::sha256(charToRaw(enc2utf8(url)))), collapse = ""), " kinds=", kinds)
}

webhook_json <- function(value) {
  httr2::response(
    status_code = 200,
    headers = "Content-Type: application/json",
    body = charToRaw(enc2utf8(as.character(jsonlite::toJSON(value, auto_unbox = TRUE, digits = 22, null = "null"))))
  )
}

# GET /account, GET /account/webhooks with `listed`, and each webhook change
# with its sealed record, which `tamper` may change.
webhook_sealing_server <- function(listed = list(list(id = 3, url = .webhook_token_url, types = list("run.refused"),
                                                     created_at = "2026-11-13T12:00:00Z")),
                                   tamper = identity) {
  function(req) {
    method <- httr2::req_get_method(req)
    path <- httr2::url_parse(httr2::req_get_url(req))$path
    body <- httr2::req_get_body(req)
    seal <- function(action, value) {
      tamper(list(format = "verdifax.account-change.v1", action = action, decided_by = "owner", key_id = 0, value = value,
                  changed_at = "2026-11-13T12:00:01Z",
                  owner_signature = c(list(public_key = .webhook_public_key), body$owner_signature),
                  signal = list(account = "account-7", sequence = 12), account_change_hash = strrep("a", 64)))
    }
    if (method == "GET" && path == "/account") {
      return(webhook_json(list(ok = TRUE, account_id = "account-7", id = 7)))
    }
    if (method == "GET" && path == "/account/webhooks") {
      return(webhook_json(list(ok = TRUE, webhooks = listed)))
    }
    if (method == "POST" && path == "/account/webhooks") {
      return(webhook_json(list(ok = TRUE, id = 3, url = body$url, types = if (is.null(body$types)) list() else body$types,
                               created_at = "2026-11-13T12:00:00Z", secret = "whsec_x", hint = "h",
                               account_change = seal("webhook.subscribed", expected_webhook_value(body$url, body$types)))))
    }
    if (method == "DELETE" && grepl("^/account/webhooks/[0-9]+$", path)) {
      hook <- listed[[1]]
      return(webhook_json(list(ok = TRUE, id = hook$id, deleted = TRUE,
                               account_change = seal("webhook.deleted", expected_webhook_value(hook$url, hook$types)))))
    }
    httr2::response(status_code = 404, headers = "Content-Type: application/json", body = charToRaw("{\"ok\":false,\"error\":\"not found\"}"))
  }
}

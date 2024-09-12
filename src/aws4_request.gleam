import gleam/bit_array
import gleam/crypto
import gleam/http
import gleam/http/request.{type Request, Request}
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/string

type DateTime =
  #(#(Int, Int, Int), #(Int, Int, Int))

pub type Signer {
  Signer(
    date_time: Option(DateTime),
    access_key_id: String,
    secret_access_key: String,
    region: String,
    service: String,
    session_token: Option(String),
  )
}

/// Create a new request signer for the given credentials, service, and region.
///
pub fn signer(
  access_key_id access_key_id: String,
  secret_access_key secret_access_key: String,
  region region: String,
  service service: String,
) -> Signer {
  Signer(
    date_time: option.None,
    access_key_id:,
    secret_access_key:,
    region:,
    service:,
    session_token: None,
  )
}

pub fn with_region(signer: Signer, region: String) -> Signer {
  Signer(..signer, region:)
}

pub fn with_service(signer: Signer, service: String) -> Signer {
  Signer(..signer, service:)
}

/// Set a session token when using temporary security credentials.
/// This sets the `x-amz-security-token` header.
///
pub fn with_session_token(signer: Signer, session_token: String) -> Signer {
  Signer(..signer, session_token: Some(session_token))
}

/// Set a specific time to use for request signing, overriding the default
/// behaviour of using the current time.
///
pub fn with_date_time(signer: Signer, date_time: DateTime) -> Signer {
  Signer(..signer, date_time: option.Some(date_time))
}

/// Sign a request that has a string body.
///
pub fn sign_string(
  signer signer: Signer,
  request request: Request(String),
) -> Request(BitArray) {
  sign_bits(signer, request.map(request, bit_array.from_string))
}

/// Sign a request that has a bit array body.
///
pub fn sign_bits(
  signer signer: Signer,
  request request: Request(BitArray),
) -> Request(BitArray) {
  let payload_hash =
    string.lowercase(
      bit_array.base16_encode(crypto.hash(crypto.Sha256, request.body)),
    )

  let #(#(year, month, day), #(hour, minute, second)) =
    option.lazy_unwrap(signer.date_time, now)

  let date =
    string.concat([
      string.pad_left(int.to_string(year), 4, "0"),
      string.pad_left(int.to_string(month), 2, "0"),
      string.pad_left(int.to_string(day), 2, "0"),
    ])
  let date_time =
    string.concat([
      date,
      "T",
      string.pad_left(int.to_string(hour), 2, "0"),
      string.pad_left(int.to_string(minute), 2, "0"),
      string.pad_left(int.to_string(second), 2, "0"),
      "Z",
    ])

  let request =
    request.set_header(request, "host", case request.port {
      option.None -> request.host
      option.Some(port) -> request.host <> ":" <> int.to_string(port)
    })

  let method = string.uppercase(http.method_to_string(request.method))

  let headers =
    request.headers
    |> add_session_token_header(signer.session_token)
    |> list.prepend(#("x-amz-date", date_time))
    |> list.prepend(#("x-amz-content-sha256", payload_hash))
    |> list.map(fn(header) { #(string.lowercase(header.0), header.1) })
    |> list.sort(fn(a, b) { string.compare(a.0, b.0) })

  let header_names =
    headers
    |> list.map(fn(h) { h.0 })
    |> string.join(";")

  let path = case request.path {
    "" -> "/"
    path -> path
  }

  let canonical_request =
    string.concat([
      method,
      "\n",
      path,
      "\n",
      option.unwrap(request.query, ""),
      "\n",
      {
        headers
        |> list.map(fn(h) { h.0 <> ":" <> h.1 })
        |> string.join("\n")
      },
      "\n",
      "\n",
      header_names,
      "\n",
      payload_hash,
    ])

  let scope =
    string.concat([
      date,
      "/",
      signer.region,
      "/",
      signer.service,
      "/aws4_request",
    ])

  let to_sign =
    string.concat([
      "AWS4-HMAC-SHA256",
      "\n",
      date_time,
      "\n",
      scope,
      "\n",
      string.lowercase(
        bit_array.base16_encode(
          crypto.hash(crypto.Sha256, <<canonical_request:utf8>>),
        ),
      ),
    ])

  let key =
    <<"AWS4":utf8, signer.secret_access_key:utf8>>
    |> crypto.hmac(<<date:utf8>>, crypto.Sha256, _)
    |> crypto.hmac(<<signer.region:utf8>>, crypto.Sha256, _)
    |> crypto.hmac(<<signer.service:utf8>>, crypto.Sha256, _)
    |> crypto.hmac(<<"aws4_request":utf8>>, crypto.Sha256, _)

  let signature =
    <<to_sign:utf8>>
    |> crypto.hmac(crypto.Sha256, key)
    |> bit_array.base16_encode
    |> string.lowercase

  let authorization =
    string.concat([
      "AWS4-HMAC-SHA256 Credential=",
      signer.access_key_id,
      "/",
      scope,
      ",SignedHeaders=" <> header_names <> ",Signature=",
      signature,
    ])

  let headers = [#("authorization", authorization), ..headers]

  Request(..request, headers: headers)
}

fn now() -> DateTime {
  system_time(1000) |> system_time_to_universal_time(1000)
}

fn add_session_token_header(headers, maybe_session_token) {
  case maybe_session_token {
    option.None -> headers
    option.Some(session_token) ->
      list.prepend(headers, #("x-amz-security-token", session_token))
  }
}

@external(erlang, "os", "system_time")
fn system_time(unit: Int) -> Int

@external(erlang, "calendar", "system_time_to_universal_time")
fn system_time_to_universal_time(
  time: Int,
  unit: Int,
) -> #(#(Int, Int, Int), #(Int, Int, Int))

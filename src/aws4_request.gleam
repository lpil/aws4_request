//// Sign requests with AWS Signature Version 4 for AWS API.

import gleam/crypto
import gleam/http
import gleam/http/request.{type Request, Request}
import gleam/int
import gleam/list
import gleam/bit_array
import gleam/option.{type Option, None, Some}
import gleam/string

/// A custom DateTime type in #((year, month, day), (hour, minute, second)) format.
pub type DateTime =
  #(#(Int, Int, Int), #(Int, Int, Int))

/// Signs a Request(BitArray) with AWS Signature Version 4 by adding signed headers,
/// and returns the signed request.
///
/// See: https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html
///
///   Parameters:
/// request: The request to sign of type Request(BitArray).
/// date_time: The current datetime in #((year, month, day), (hour, minute, second)) format.
/// access_key_id: The AWS credential access key ID being used to authenticate the request.
/// secret_access_key: The AWS credential secret access key being used to authenticate the
/// request.
/// session_token: (Optional) The security token value if using temporary credentials from AWS STS.
/// region: The AWS region that the request will be made to.
/// service: The AWS service name that the request is for.
pub fn sign_bits(
  request request: Request(BitArray),
  date_time date_time: DateTime,
  access_key_id access_key_id: String,
  secret_access_key secret_access_key: String,
  session_token session_token: Option(String),
  region region: String,
  service service: String,
) -> Request(BitArray) {
  sign(
    request,
    request.body,
    date_time,
    access_key_id,
    secret_access_key,
    session_token,
    region,
    service,
  )
}

/// Signs a Request(String) with AWS Signature Version 4 by adding signed headers,
/// and returns the signed request.
///
/// See: https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html
///
///   Parameters:
/// request: The request to sign of type Request(BitArray).
/// date_time: The current datetime in #((year, month, day), (hour, minute, second)) format.
/// access_key_id: The AWS credential access key ID being used to authenticate the request.
/// secret_access_key: The AWS credential secret access key being used to authenticate the
/// request.
/// session_token: (Optional) The security token value if using temporary credentials from AWS STS.
/// region: The AWS region that the request will be made to.
/// service: The AWS service name that the request is for.
pub fn sign_string(
  request request: Request(String),
  date_time date_time: DateTime,
  access_key_id access_key_id: String,
  secret_access_key secret_access_key: String,
  session_token session_token: Option(String),
  region region: String,
  service service: String,
) -> Request(String) {
  let body = bit_array.from_string(request.body)
  sign(
    request,
    body,
    date_time,
    access_key_id,
    secret_access_key,
    session_token,
    region,
    service,
  )
}

/// See: https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html
///
/// Internal function that uses custom union type BitArrayOrString to handle requests
/// of both type Request(BitArray) and type Request(String).
///
///   Parameters:
/// request: The request to sign of type Request(BitArray).
/// body: The request body as a BitArray for content hash generation.
/// date_time: The current datetime in #((year, month, day), (hour, minute, second)) format.
/// access_key_id: The AWS credential access key ID being used to authenticate the request.
/// secret_access_key: The AWS credential secret access key being used to authenticate the
/// request.
/// session_token: (Optional) The security token value if using temporary credentials from AWS STS.
/// region: The AWS region that the request will be made to.
/// service: The AWS service name that the request is for.
fn sign(
  request request: Request(a),
  body body: BitArray,
  date_time date_time: DateTime,
  access_key_id access_key_id: String,
  secret_access_key secret_access_key: String,
  session_token session_token: Option(String),
  region region: String,
  service service: String,
) -> Request(a) {
  let payload_hash =
    string.lowercase(bit_array.base16_encode(crypto.hash(crypto.Sha256, body)))

  let #(#(year, month, day), #(hour, minute, second)) = date_time
  let date =
    string.concat([
      string.pad_left(int.to_string(year), 4, "0"),
      string.pad_left(int.to_string(month), 2, "0"),
      string.pad_left(int.to_string(day), 2, "0"),
    ])
  let iso_8016_date_time =
    string.concat([
      date,
      "T",
      string.pad_left(int.to_string(hour), 2, "0"),
      string.pad_left(int.to_string(minute), 2, "0"),
      string.pad_left(int.to_string(second), 2, "0"),
      "Z",
    ])
  let method = string.uppercase(http.method_to_string(request.method))
  let base_headers = [
    #("x-amz-date", iso_8016_date_time),
    #("x-amz-content-sha256", payload_hash),
  ]
  let auth_headers = case session_token {
    Some(token) -> [#("x-amz-security-token", token), ..base_headers]
    None -> base_headers
  }
  let headers =
    request.headers
    |> list.append(auth_headers)
    |> list.map(fn(header) { #(string.lowercase(header.0), header.1) })
    |> list.sort(fn(a, b) { string.compare(a.0, b.0) })

  let canonical_headers =
    headers
    |> list.map(fn(h) { h.0 <> ":" <> h.1 })
    |> string.join("\n")

  let header_names =
    headers
    |> list.map(fn(h) { h.0 })
    |> string.join(";")

  // Step 1: Create a canonical request
  let canonical_request =
    [
      method,
      // HTTPMethod
      request.path,
      // CanonicalURI
      option.unwrap(request.query, ""),
      // CanonicalQueryString
        canonical_headers <> "\n",
      // CanonicalHeaders
      header_names,
      // SignedHeaders
      payload_hash,
    ]
    // HashedPayload
    |> string.join("\n")

  // Step 2: Create a hash of the canonical request
  let hashed_canonical_request =
    string.lowercase(
      bit_array.base16_encode(
        crypto.hash(crypto.Sha256, <<canonical_request:utf8>>),
      ),
    )

  // Step 3: Create a string to sign
  let scope = string.concat([date, "/", region, "/", service, "/aws4_request"])
  let to_sign =
    ["AWS4-HMAC-SHA256", iso_8016_date_time, scope, hashed_canonical_request]
    |> string.join("\n")

  // Step 4: Calculate the signature
  let key =
    <<"AWS4":utf8, secret_access_key:utf8>>
    |> crypto.hmac(<<date:utf8>>, crypto.Sha256, _)
    |> crypto.hmac(<<region:utf8>>, crypto.Sha256, _)
    |> crypto.hmac(<<service:utf8>>, crypto.Sha256, _)
    |> crypto.hmac(<<"aws4_request":utf8>>, crypto.Sha256, _)

  let signature =
    <<to_sign:utf8>>
    |> crypto.hmac(crypto.Sha256, key)
    |> bit_array.base16_encode
    |> string.lowercase

  // Step 5: Add the signature to the request
  let credential = access_key_id <> "/" <> scope
  let authorization =
    [
      "AWS4-HMAC-SHA256 Credential=" <> credential,
      "SignedHeaders=" <> header_names,
      "Signature=" <> signature,
    ]
    |> string.join(",")

  let updated_headers = [#("authorization", authorization), ..headers]

  Request(..request, headers: updated_headers)
}

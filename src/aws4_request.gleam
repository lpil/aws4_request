import gleam/crypto
import gleam/http
import gleam/http/request.{type Request, Request}
import gleam/int
import gleam/list
import gleam/bit_array
import gleam/option
import gleam/string

// TODO: document
// TODO: document params
// https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html
pub fn sign_bits(
  request request: Request(BitArray),
  date_time date_time: #(#(Int, Int, Int), #(Int, Int, Int)),
  access_key_id access_key_id: String,
  secret_access_key secret_access_key: String,
  region region: String,
  service service: String,
) -> Request(BitArray) {
  sign(
    request,
    request.body,
    date_time,
    access_key_id,
    secret_access_key,
    region,
    service,
  )
}

pub fn sign_string(
  request request: Request(String),
  date_time date_time: #(#(Int, Int, Int), #(Int, Int, Int)),
  access_key_id access_key_id: String,
  secret_access_key secret_access_key: String,
  region region: String,
  service service: String,
) -> Request(String) {
  let body_as_bit_array = bit_array.from_string(request.body)
  sign(
    request,
    body_as_bit_array,
    date_time,
    access_key_id,
    secret_access_key,
    region,
    service,
  )
}

fn sign(
  request request: Request(a),
  body body: BitArray,
  date_time date_time: #(#(Int, Int, Int), #(Int, Int, Int)),
  access_key_id access_key_id: String,
  secret_access_key secret_access_key: String,
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
  let date_time =
    string.concat([
      date,
      "T",
      string.pad_left(int.to_string(hour), 2, "0"),
      string.pad_left(int.to_string(minute), 2, "0"),
      string.pad_left(int.to_string(second), 2, "0"),
      "Z",
    ])

  let method = string.uppercase(http.method_to_string(request.method))
  let headers =
    request.headers
    |> list.prepend(#("x-amz-date", date_time))
    |> list.prepend(#("x-amz-content-sha256", payload_hash))
    |> list.map(fn(header) { #(string.lowercase(header.0), header.1) })
    |> list.sort(fn(a, b) { string.compare(a.0, b.0) })

  let header_names =
    headers
    |> list.map(fn(h) { h.0 })
    |> string.join(";")

  let canonical_request =
    string.concat([
      method,
      "\n",
      request.path,
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

  let scope = string.concat([date, "/", region, "/", service, "/aws4_request"])

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

  let authorization =
    string.concat([
      "AWS4-HMAC-SHA256 Credential=",
      access_key_id,
      "/",
      scope,
      ",SignedHeaders=" <> header_names <> ",Signature=",
      signature,
    ])

  let headers = [#("authorization", authorization), ..headers]

  Request(..request, headers: headers)
}

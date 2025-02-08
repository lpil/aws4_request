# Changelog

## v1.2.2 - 2025-02-08

- Update standard lib to use new `string.pad_start` function.

## v1.2.1 - 2025-02-06

- Relaxed the constraint for `gleam_http` to permit v4.

## v1.2.0 - 2024-11-25

- Support for the JavaScript target added.

## v1.1.0 - 2024-09-17

- Added a convenience function for setting a session token for when using
  temporary credentials.

## v1.0.0 - 2024-08-29

- The API of the package has been changed.
- The `host` header is now set for you.
- The date time parameter is now optional, the current date is used if one is
  not provided.

## v0.1.1 - 2024-08-29

- Corrected a pub where requests with no path would not be signed correctly.

## v0.1.1 - 2024-01-16

- Relaxed constraints on `gleam_stdlib` and `gleam_crypto` to permit v0.x or v1.x
  releases.

## v0.1.0 - 2023-11-12

- Initial release.

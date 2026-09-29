# BUGS

No known bugs.

Limitations (tracked in TODO.md):

- GitHub connector reads only the first 100 repos; no pagination yet.
- Local connector may false-positive on test fixtures that contain
  credential-shaped strings.
- Web connector checks only `/` for security headers.

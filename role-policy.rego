package example

default allow = false

allow {
  input.user.role == "admin"
}

allow {
  input.user.role == "editor"
}
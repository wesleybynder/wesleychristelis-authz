package example

import rego.v1

default allow := false

allow if {
	"admin" in input.user.role
}
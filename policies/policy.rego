# package example

# default allow = false

# # Allow access if the user has the role "admin"
# allow {
#   input.user.role == "admin"
# }
package policy

import future.keywords.if
import future.keywords.in

is_admin if {
    "admin" in input.user.roles
}
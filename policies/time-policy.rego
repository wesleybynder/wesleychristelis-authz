package example

import time.now

default allow = false

allow {
  hour := now().hour
  hour >= 9
  hour < 17
}
// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import "expvar"

var (
	counterNumRequests = expvar.NewInt("counter_num_requests")
	counterNumDenied   = expvar.NewInt("counter_num_denied")
)

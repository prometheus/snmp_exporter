// Copyright 2026 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package remotewrite

import (
	"context"
	"errors"
	"fmt"
	"net/http"
)

type retryableError interface {
	Retryable() bool
}

type transportError struct{}

func (transportError) Error() string   { return "remote write transport request failed" }
func (transportError) Retryable() bool { return true }

type permanentError struct {
	message string
}

func (e permanentError) Error() string { return e.message }
func (permanentError) Retryable() bool { return false }

// HTTPError reports only the response status and never includes a response
// body that could contain sensitive downstream details.
type HTTPError struct {
	StatusCode int
}

func (e HTTPError) Error() string {
	return fmt.Sprintf("remote write returned HTTP status %d %s", e.StatusCode, http.StatusText(e.StatusCode))
}

func (e HTTPError) Retryable() bool {
	return e.StatusCode == 429 || e.StatusCode >= 500
}

// IsRetryable classifies errors for output.AsyncOutput.
func IsRetryable(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	var classified retryableError
	if errors.As(err, &classified) {
		return classified.Retryable()
	}
	return false
}

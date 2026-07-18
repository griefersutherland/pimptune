package ms

import (
	"context"
	"net/http"
	"time"

	"github.com/griefersutherland/pimptune/internal/utils"
	"github.com/rs/zerolog/log"
)

const (
	maxRetries    = 2
	retryBaseWait = 500 * time.Millisecond
)

// isRetryableStatus determines if an HTTP status code should trigger a retry
func isRetryableStatus(status int) bool {
	switch status {
	case 0,
		http.StatusTooManyRequests,     // 429
		http.StatusInternalServerError, // 500
		http.StatusBadGateway,          // 502
		http.StatusServiceUnavailable,  // 503
		http.StatusGatewayTimeout:      // 504
		return true
	}
	return false
}

// postJsonWithRetry wraps utils.PostJson with exponential backoff on transient failures.
// The same activity ID in headers is preserved across retries for Intune log correlation.
func (c *MSClient) postJsonWithRetry(
	ctx context.Context,
	url string,
	headers map[string]string,
	reqObj any,
	resObj any,
) (status int, hdr http.Header, body []byte, err error) {
	wait := retryBaseWait
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			log.Warn().
				Int("attempt", attempt+1).
				Int("prev_status", status).
				Dur("backoff", wait).
				Str("url", url).
				Msg("Retrying Intune API call after transient error")
			select {
			case <-ctx.Done():
				return 0, nil, nil, ctx.Err()
			case <-time.After(wait):
			}
			wait *= 2
		}

		_, status, hdr, body, err = utils.PostJson(ctx, c.httpClient, url, headers, reqObj, resObj)
		if err == nil || !isRetryableStatus(status) {
			break
		}
	}
	return status, hdr, body, err
}

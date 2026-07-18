package cli

// removed rate limit middleware, let the front end reverse proxy handle it

/*
import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/griefersutherland/pimptune/internal/utils"
	"golang.org/x/time/rate"
)

type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

var (
	visitors        = make(map[string]*visitor)
	visitorsMu      sync.Mutex
	visitorsCleanup sync.Once
)

func middlewareRateLimit(ctx context.Context, limit rate.Limit, burst int) func(http.Handler) http.Handler {
	visitorsCleanup.Do(func() {
		go func() {
			ticker := time.NewTicker(time.Minute)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					visitorsMu.Lock()
					for ip, v := range visitors {
						if time.Since(v.lastSeen) > 3*time.Minute {
							delete(visitors, ip)
						}
					}
					visitorsMu.Unlock()
				case <-ctx.Done():
					return
				}
			}
		}()
	})

	getVisitor := func(ip string) *rate.Limiter {
		visitorsMu.Lock()
		defer visitorsMu.Unlock()

		if v, exists := visitors[ip]; exists {
			v.lastSeen = time.Now()
			return v.limiter
		}

		lim := rate.NewLimiter(limit, burst)
		visitors[ip] = &visitor{
			limiter:  lim,
			lastSeen: time.Now(),
		}
		return lim
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := utils.GetRequestSourceIP(r)
			lim := getVisitor(ip)
			if !lim.Allow() {
				http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
*/

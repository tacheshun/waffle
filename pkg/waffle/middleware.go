package waffle

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/labstack/echo/v4"
)

// Middleware returns a standard net/http middleware function
func (w *Waffle) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		// Process the request through the WAF
		blocked, reason := w.Process(r)

		if blocked {
			// Request is blocked
			if w.options.blockHandler != nil {
				// Use custom block handler if provided
				w.options.blockHandler(reason)
			} else {
				// Default block behavior
				rw.WriteHeader(http.StatusForbidden)
				_, err := rw.Write([]byte("Forbidden: " + reason.Message))
				if err != nil {
					// If write fails, we've already sent the header
					// Log would be appropriate here in production code
				}

				// If rate limited, add retry-after header
				if reason.Rule == "rate_limit" && reason.Wait > 0 {
					rw.Header().Set("Retry-After", time.Now().Add(time.Duration(reason.Wait)*time.Second).Format(time.RFC1123))
				}
			}
			return
		}

		// Request is allowed, proceed to next handler
		next.ServeHTTP(rw, r)
	})
}

// HandlerFunc returns a standard net/http middleware function for use with http.HandleFunc
func (w *Waffle) HandlerFunc(next http.HandlerFunc) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		// Process the request through the WAF
		blocked, reason := w.Process(r)

		if blocked {
			// Request is blocked
			if w.options.blockHandler != nil {
				// Use custom block handler if provided
				w.options.blockHandler(reason)
			} else {
				// Default block behavior
				rw.WriteHeader(http.StatusForbidden)
				_, err := rw.Write([]byte("Forbidden: " + reason.Message))
				if err != nil {
					// If write fails, we've already sent the header
				}

				// If rate limited, add retry-after header
				if reason.Rule == "rate_limit" && reason.Wait > 0 {
					rw.Header().Set("Retry-After", time.Now().Add(time.Duration(reason.Wait)*time.Second).Format(time.RFC1123))
				}
			}
			return
		}

		// Request is allowed, proceed to next handler
		next(rw, r)
	}
}

// GinMiddleware returns a middleware function for use with the Gin framework
func (w *Waffle) GinMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Process the request through the WAF
		blocked, reason := w.Process(c.Request)

		if blocked {
			// Request is blocked
			if w.options.blockHandler != nil {
				// Use custom block handler if provided
				w.options.blockHandler(reason)
				c.Abort()
			} else {
				// Default block behavior
				c.AbortWithStatus(http.StatusForbidden)
				c.String(http.StatusForbidden, "Forbidden: "+reason.Message)

				// If rate limited, add retry-after header
				if reason.Rule == "rate_limit" && reason.Wait > 0 {
					c.Header("Retry-After", time.Now().Add(time.Duration(reason.Wait)*time.Second).Format(time.RFC1123))
				}
			}
			return
		}

		// Request is allowed, proceed to next handler
		c.Next()
	}
}

// EchoMiddleware returns a middleware function for use with the Echo framework
func (w *Waffle) EchoMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Process the request through the WAF
			blocked, reason := w.Process(c.Request())

			if blocked {
				// Request is blocked
				if w.options.blockHandler != nil {
					// Use custom block handler if provided
					w.options.blockHandler(reason)
					return nil
				}

				// If rate limited, add retry-after header
				if reason.Rule == "rate_limit" && reason.Wait > 0 {
					c.Response().Header().Set("Retry-After",
						time.Now().Add(time.Duration(reason.Wait)*time.Second).Format(time.RFC1123))
				}

				return c.String(http.StatusForbidden, "Forbidden: "+reason.Message)
			}

			// Request is allowed, proceed to next handler
			return next(c)
		}
	}
}

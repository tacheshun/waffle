package waffle

import (
	"fmt"
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
			// Log the block event
			w.logger.LogAttack(r, reason)

			// Request is blocked
			if w.options.blockHandler != nil {
				// Use custom block handler if provided
				w.options.blockHandler(reason)
			} else {
				// Default block behavior
				header := rw.Header()

				// If rate limited, add retry-after header
				if reason.Rule == "rate_limit" && reason.Wait > 0 {
					retryAfter := time.Now().Add(time.Duration(reason.Wait) * time.Second).Format(time.RFC1123)
					header.Set("Retry-After", retryAfter)
				}

				// Set content type before writing status
				header.Set("Content-Type", "text/plain; charset=utf-8")
				rw.WriteHeader(http.StatusForbidden)

				msg := fmt.Sprintf("Forbidden: %s", reason.Message)
				if _, err := rw.Write([]byte(msg)); err != nil {
					w.logger.LogError(fmt.Errorf("failed to write response: %w", err))
				}
			}
			return
		}

		// Log allowed request if configured
		if w.options.logAllRequests {
			w.logger.LogRequest(r)
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
			// Log the block event
			w.logger.LogAttack(r, reason)

			// Request is blocked
			if w.options.blockHandler != nil {
				// Use custom block handler if provided
				w.options.blockHandler(reason)
			} else {
				// Default block behavior
				header := rw.Header()

				// If rate limited, add retry-after header
				if reason.Rule == "rate_limit" && reason.Wait > 0 {
					retryAfter := time.Now().Add(time.Duration(reason.Wait) * time.Second).Format(time.RFC1123)
					header.Set("Retry-After", retryAfter)
				}

				// Set content type before writing status
				header.Set("Content-Type", "text/plain; charset=utf-8")
				rw.WriteHeader(http.StatusForbidden)

				msg := fmt.Sprintf("Forbidden: %s", reason.Message)
				if _, err := rw.Write([]byte(msg)); err != nil {
					w.logger.LogError(fmt.Errorf("failed to write response: %w", err))
				}
			}
			return
		}

		// Log allowed request if configured
		if w.options.logAllRequests {
			w.logger.LogRequest(r)
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
			// Log the block event
			w.logger.LogAttack(c.Request, reason)

			// Request is blocked
			if w.options.blockHandler != nil {
				// Use custom block handler if provided
				w.options.blockHandler(reason)
				c.Abort()
			} else {
				// If rate limited, add retry-after header
				if reason.Rule == "rate_limit" && reason.Wait > 0 {
					retryAfter := time.Now().Add(time.Duration(reason.Wait) * time.Second).Format(time.RFC1123)
					c.Header("Retry-After", retryAfter)
				}

				// Default block behavior with proper content type
				c.Header("Content-Type", "text/plain; charset=utf-8")
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"error":   "Forbidden",
					"message": reason.Message,
					"rule":    reason.Rule,
				})
			}
			return
		}

		// Log allowed request if configured
		if w.options.logAllRequests {
			w.logger.LogRequest(c.Request)
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
				// Log the block event
				w.logger.LogAttack(c.Request(), reason)

				// Request is blocked
				if w.options.blockHandler != nil {
					// Use custom block handler if provided
					w.options.blockHandler(reason)
					return nil
				}

				// If rate limited, add retry-after header
				if reason.Rule == "rate_limit" && reason.Wait > 0 {
					retryAfter := time.Now().Add(time.Duration(reason.Wait) * time.Second).Format(time.RFC1123)
					c.Response().Header().Set("Retry-After", retryAfter)
				}

				// Return a JSON response with proper status and content type
				return c.JSON(http.StatusForbidden, map[string]interface{}{
					"error":   "Forbidden",
					"message": reason.Message,
					"rule":    reason.Rule,
				})
			}

			// Log allowed request if configured
			if w.options.logAllRequests {
				w.logger.LogRequest(c.Request())
			}

			// Request is allowed, proceed to next handler
			return next(c)
		}
	}
}

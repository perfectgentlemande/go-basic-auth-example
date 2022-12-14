package logger

import (
	"context"
	"net/http"
	"os"

	"github.com/sirupsen/logrus"
)

type loggerCtxKey struct{}

func DefaultLogger() *logrus.Entry {
	log := logrus.New()
	log.SetOutput(os.Stdout)
	log.SetFormatter(&logrus.JSONFormatter{})

	return logrus.NewEntry(log)
}

func WithLogger(ctx context.Context, log *logrus.Entry) context.Context {
	return context.WithValue(ctx, loggerCtxKey{}, log)
}
func GetLogger(ctx context.Context) *logrus.Entry {
	le, ok := ctx.Value(loggerCtxKey{}).(*logrus.Entry)
	if !ok {
		le = DefaultLogger()
	}
	return le
}

func NewLoggingMiddleware(log *logrus.Entry) func(http.Handler) http.Handler {
	return func(handler http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextLog := log.WithFields(logrus.Fields{
				"method": r.Method,
				"path":   r.URL.Path,
			})

			handler.ServeHTTP(w, r.WithContext(WithLogger(r.Context(), nextLog)))
		})
	}
}

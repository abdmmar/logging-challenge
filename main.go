package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	signal.Notify(ch, syscall.SIGTERM)
	go func() {
		oscall := <-ch
		log.Warn().Msgf("system call:%+v", oscall)
		cancel()
	}()

	r := mux.NewRouter()

	r.Use(LogMiddleware)
	r.HandleFunc("/", handler)

	lf, err := os.OpenFile("logs/app.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)

	if err != nil {
		log.Fatal().Err(err).Msg("unable to open log file")
	}

	if os.Getenv("LOG_LEVEL") == "debug" {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	multiWriters := zerolog.MultiLevelWriter(os.Stdout, lf)
	log.Logger = zerolog.New(multiWriters).With().Timestamp().Caller().Logger()

	server := &http.Server{
		Addr:    ":8080",
		Handler: r,
	}
	log.Info().Msg("Sever is ready and listen on http://localhost:8080")

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("failed to listen and serve http server")
		}
	}()
	<-ctx.Done()

	if err := server.Shutdown(context.Background()); err != nil {
		log.Error().Err(err).Msg("failed to shutdown http server gracefully")
	}
}

func LogMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := uuid.New().String()
		fullURL := r.URL.Path
		if r.URL.RawQuery != "" {
			fullURL += "?" + r.URL.RawQuery
		}
		log := log.With().Str("request_id", requestID).Str("method", r.Method).
			Str("url", fullURL).Logger()
		ctx := log.WithContext(r.Context())
		log.Debug().Ctx(ctx).Msg("Incoming request")
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func handler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := zerolog.Ctx(ctx)
	name := r.URL.Query().Get("name")
	res, err := greeting(ctx, name)
	if err != nil {
		logger.Error().Ctx(ctx).Msg(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write([]byte(res))
}

func getFnName() string {
	pc, _, _, ok := runtime.Caller(1)
	if !ok {
		return "unknown"
	}
	funcname := runtime.FuncForPC(pc).Name()
	fn := funcname[strings.LastIndex(funcname, ".")+1:]
	return fn
}

func greeting(ctx context.Context, name string) (string, error) {
	logger := zerolog.Ctx(ctx)
	if len(name) < 5 {
		logger.Warn().Ctx(ctx).Str("func", getFnName()).Msg("name is too short!")
		return fmt.Sprintf("Hello %s! Your name is to short\n", name), nil
	}
	logger.Info().Ctx(ctx).Str("func", getFnName()).Msgf("Hi %s", name)
	return fmt.Sprintf("Hi %s", name), nil
}

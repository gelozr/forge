package log

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Config struct {
	LogLevel  string
	LogFormat string
	LogPath   string
	LogOutput string
}

type SlogLogger struct {
	logger *slog.Logger
	closer io.Closer
}

var _ Logger = (*SlogLogger)(nil)

func getConfig(cfg ...Config) Config {
	var c Config
	if len(cfg) > 0 {
		c = cfg[0]
	}

	if c.LogLevel == "" {
		c.LogLevel = "info"
	}

	if c.LogFormat == "" {
		c.LogFormat = "text"
	}

	if c.LogOutput == "" {
		c.LogOutput = "stdout"
	}

	if c.LogPath == "" {
		c.LogPath = "./log/app.log"
	}

	return c
}

func NewSlogLogger(c ...Config) (*SlogLogger, error) {
	var (
		w      io.Writer = os.Stdout
		closer io.Closer
	)

	cfg := getConfig(c...)

	out, err := setOutput(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to set output: %w", err)
	}
	if out != nil {
		w, closer = out, out
	}

	var h slog.Handler

	level := slog.LevelInfo
	switch strings.ToLower(cfg.LogLevel) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}

	if cfg.LogFormat == "json" {
		h = slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level, ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				t := a.Value.Time()
				a.Value = slog.StringValue(t.Format(time.DateTime))
			}
			return a
		}})
	} else {
		h = slog.NewTextHandler(w, &slog.HandlerOptions{Level: level})
	}

	h = &ctxHandler{base: h}

	sloglogger := slog.New(h)

	return &SlogLogger{logger: sloglogger, closer: closer}, nil
}

func (l SlogLogger) With(args ...any) Logger {
	return SlogLogger{logger: l.logger.With(args...)}
}

func (l SlogLogger) Debug(msg string, args ...any) {
	l.logger.Debug(msg, args...)
}

func (l SlogLogger) Info(msg string, args ...any) {
	l.logger.Info(msg, args...)
}

func (l SlogLogger) Warn(msg string, args ...any) {
	l.logger.Warn(msg, args...)
}

func (l SlogLogger) Error(msg string, args ...any) {
	l.logger.Error(msg, args...)
}

func (l SlogLogger) DebugContext(ctx context.Context, msg string, args ...any) {
	l.logger.DebugContext(ctx, msg, args...)
}

func (l SlogLogger) InfoContext(ctx context.Context, msg string, args ...any) {
	l.logger.InfoContext(ctx, msg, args...)
}

func (l SlogLogger) WarnContext(ctx context.Context, msg string, args ...any) {
	l.logger.WarnContext(ctx, msg, args...)
}

func (l SlogLogger) ErrorContext(ctx context.Context, msg string, args ...any) {
	l.logger.ErrorContext(ctx, msg, args...)
}

func (l SlogLogger) Close() error {
	if l.closer != nil {
		return l.closer.Close()
	}
	return nil
}

func setOutput(cfg Config) (io.WriteCloser, error) {
	var w io.WriteCloser

	if strings.EqualFold(cfg.LogOutput, "file") {
		if err := os.MkdirAll(filepath.Dir(cfg.LogPath), 0o755); err != nil {
			return nil, fmt.Errorf("create output dir: %w", err)
		}
		f, err := os.OpenFile(cfg.LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return nil, fmt.Errorf("open output file: %w", err)
		}
		w = f
	}

	return w, nil
}

type ctxHandler struct {
	base slog.Handler
}

func (h *ctxHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.base.Enabled(ctx, level)
}

func (h *ctxHandler) Handle(ctx context.Context, r slog.Record) error {
	return h.base.Handle(ctx, r)
}

func (h *ctxHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &ctxHandler{base: h.base.WithAttrs(attrs)}
}

func (h *ctxHandler) WithGroup(name string) slog.Handler {
	return &ctxHandler{base: h.base.WithGroup(name)}
}

package log

import (
	"context"
	"log/slog"
	"strings"

	"github.com/regclient/regclient/types"
	"github.com/rs/zerolog"
)

type zotHandler struct {
	logger Logger
	attrs  []slog.Attr
	groups []string
}

func NewHandler(logger Logger) *zotHandler {
	return &zotHandler{
		logger: logger,
	}
}

// Enabled reports whether the handler handles records at the given level.
// The handler ignores records whose level is lower. It uses mapping between
// Zerolog levels and Slog levels.
func (h *zotHandler) Enabled(_ context.Context, recordLevel slog.Level) bool {
	zerologToSlog := map[zerolog.Level]slog.Level{
		zerolog.TraceLevel: types.LevelTrace,
		zerolog.DebugLevel: slog.LevelDebug,
		zerolog.InfoLevel:  slog.LevelInfo,
		zerolog.WarnLevel:  slog.LevelWarn,
		zerolog.ErrorLevel: slog.LevelError,
		zerolog.FatalLevel: slog.LevelError + 4,
		zerolog.PanicLevel: slog.LevelError + 8,
		zerolog.NoLevel:    slog.LevelError + 12,
		zerolog.Disabled:   slog.LevelError + 16,
	}

	loggerLevel, ok := zerologToSlog[h.logger.GetLevel()]

	if !ok {
		return true
	}

	return recordLevel >= loggerLevel
}

func (h *zotHandler) Handle(ctx context.Context, rec slog.Record) error {
	attrsJoin := make([]slog.Attr, 0, len(h.attrs)+rec.NumAttrs())

	// Join handler and record attributes. Handler attributes
	// should already be qualified with group names. The same
	// must apply to the record attributes.
	attrsJoin = append(attrsJoin, h.attrs...)

	rec.Attrs(func(attr slog.Attr) bool {
		prefix := ""
		if len(h.groups) > 0 {
			prefix = strings.Join(h.groups, ":") + ":"
		}

		if attr.Value.Kind() == slog.KindGroup {
			prefix += attr.Key + ":"

			attrsJoin = append(attrsJoin, flatten(prefix, attr.Value.Group()...)...)
		} else {
			attrsJoin = append(attrsJoin, slog.Attr{
				Key:   prefix + attr.Key,
				Value: attr.Value,
			})
		}

		return true
	})

	// Create a Zerolog event
	event := h.logger.
		WithLevel(slogToZerolog(rec.Level)).
		Ctx(ctx).
		CallerSkipFrame(3)

	if !rec.Time.IsZero() {
		event.Time(zerolog.TimestampFieldName, rec.Time)
	}

	// If attributes are provided turn them into fields
	// map and add such map the event. The attrsJoin
	// should contain flatten arguments at this point.
	if len(attrsJoin) > 0 {
		fields := map[string]any{}

		for _, attr := range attrsJoin {
			fields[attr.Key] = attr.Value.Any()
		}

		event.Fields(fields)
	}

	// Log message
	event.Msg(rec.Message)

	return nil
}

// WithAttr returns a zotHandler whose attributes consist of both
// the receiver's attributes and the arguments. The qualification
// happens by "flattening" the group-kind attributes, by extracting
// their nested attributes into new keys prefixed with colon-separated
// groups names sequence.
func (h *zotHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	newHandler := &zotHandler{
		logger: h.logger,
		attrs:  make([]slog.Attr, len(h.attrs)),
		groups: make([]string, len(h.groups)),
	}

	copy(newHandler.attrs, h.attrs)
	copy(newHandler.groups, h.groups)

	prefix := ""
	if len(h.groups) > 0 {
		prefix = strings.Join(h.groups, ":") + ":"
	}

	for _, attr := range attrs {
		if attr.Key == "" {
			continue
		}

		if attr.Value.Kind() == slog.KindGroup {
			prefix += attr.Key + ":"

			newHandler.attrs = append(newHandler.attrs, flatten(prefix, attr.Value.Group()...)...)
		} else {
			newHandler.attrs = append(newHandler.attrs, slog.Attr{
				Key:   prefix + attr.Key,
				Value: attr.Value,
			})
		}
	}

	return newHandler
}

// WithGroup returns a new Handler with the given group appended to
// the receiver's existing groups.
func (h *zotHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}

	newHandler := &zotHandler{
		logger: h.logger,
		attrs:  make([]slog.Attr, len(h.attrs)),
		groups: make([]string, len(h.groups)),
	}

	copy(newHandler.attrs, h.attrs)
	copy(newHandler.groups, h.groups)

	newHandler.groups = append(newHandler.groups, name)

	return newHandler
}

func flatten(prefix string, attrs ...slog.Attr) []slog.Attr {
	res := []slog.Attr{}

	for _, attr := range attrs {
		if attr.Value.Kind() == slog.KindGroup {
			res = append(res, flatten(prefix+attr.Key+":", attr.Value.Group()...)...)
		} else {
			res = append(res, slog.Attr{
				Key:   prefix + attr.Key,
				Value: attr.Value,
			})
		}
	}

	return res
}

func slogToZerolog(level slog.Level) zerolog.Level {
	switch {
	case level <= types.LevelTrace:
		return zerolog.TraceLevel
	case level <= slog.LevelDebug:
		return zerolog.DebugLevel
	case level <= slog.LevelInfo:
		return zerolog.InfoLevel
	case level <= slog.LevelWarn:
		return zerolog.WarnLevel
	case level <= slog.LevelError:
		return zerolog.ErrorLevel
	case level <= slog.LevelError+4:
		return zerolog.FatalLevel
	case level <= slog.LevelError+8:
		return zerolog.PanicLevel
	case level <= slog.LevelError+12:
		return zerolog.NoLevel
	default:
		return zerolog.Disabled
	}
}

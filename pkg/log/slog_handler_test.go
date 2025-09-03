package log_test

import (
	"bytes"
	"context"
	"log/slog"
	"regexp"
	"strings"
	"testing"

	"github.com/regclient/regclient/types"
	"github.com/rs/zerolog"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/pkg/log"
)

const jsonTimeRE = `\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})`

func TestSlogHandler(t *testing.T) {
	testCases := []struct {
		name         string
		zerologLevel zerolog.Level
		slogLevel    slog.Level
	}{
		{
			name:         "trace",
			zerologLevel: zerolog.TraceLevel,
			slogLevel:    types.LevelTrace,
		},
		{
			name:         "debug",
			zerologLevel: zerolog.DebugLevel,
			slogLevel:    slog.LevelDebug,
		},
		{
			name:         "info",
			zerologLevel: zerolog.InfoLevel,
			slogLevel:    slog.LevelInfo,
		},
		{
			name:         "warn",
			zerologLevel: zerolog.WarnLevel,
			slogLevel:    slog.LevelWarn,
		},
		{
			name:         "error",
			zerologLevel: zerolog.ErrorLevel,
			slogLevel:    slog.LevelError,
		},
		{
			name:         "fatal",
			zerologLevel: zerolog.FatalLevel,
			slogLevel:    slog.LevelError + 4,
		},
	}

	Convey("Test slog Handler", t, func() {
		for _, test := range testCases {
			ctx := context.Background()

			out := &bytes.Buffer{}

			zerolog.SetGlobalLevel(test.zerologLevel)

			zotLogger := log.Logger{Logger: zerolog.New(out)}

			slogLogger := slog.New(log.NewHandler(zotLogger))

			check := func(level, want string) {
				t.Helper()

				if want != "" {
					want = `{"level":"` + level + `","time":"` + jsonTimeRE + `",` + want + `}`
				}

				checkLogOutput(t, out.String(), want)
				out.Reset()
			}

			// Check basic combinations of attributes and levels

			slogLogger.Log(ctx, types.LevelTrace, "trace record with no attributes")

			if test.slogLevel <= types.LevelTrace {
				check(
					"trace",
					`"message":"trace record with no attributes"`,
				)
			} else {
				check("", ``)
			}

			slogLogger.Debug("debug record with a single attribute", "str", "value")

			if test.slogLevel <= slog.LevelDebug {
				check(
					"debug",
					`"str":"value","message":"debug record with a single attribute"`,
				)
			} else {
				check("", ``)
			}

			slogLogger.Info("info record with a single group attribute",
				slog.Group("group", slog.String("str", "value"), slog.Int("int", 5)))

			if test.slogLevel <= slog.LevelInfo {
				check(
					"info",
					`"group:int":5,"group:str":"value","message":"info record with a single group attribute"`,
				)
			} else {
				check("", ``)
			}

			slogLogger.Warn("warn record with more attributes", "str", "value", "int", 2)

			if test.slogLevel <= slog.LevelWarn {
				check(
					"warn",
					`"int":2,"str":"value","message":"warn record with more attributes"`,
				)
			} else {
				check("", ``)
			}

			slogLogger.Error("error record with a nested groups",
				slog.Group("group1", slog.String("str1", "value1"), slog.Int("int1", 5)),
				slog.Group("group2", slog.String("str2", "value2"), slog.Group("group3", slog.Int("int2", 10))),
			)

			if test.slogLevel <= slog.LevelError {
				check(
					"error",
					`"group1:int1":5,"group1:str1":"value1","group2:group3:int2":10,`+
						`"group2:str2":"value2","message":"error record with a nested groups"`,
				)
			} else {
				check("", ``)
			}

			// Adding group and attributes to handler and check again
			slogLogger = slog.New(
				slogLogger.Handler().WithGroup("base").WithAttrs([]slog.Attr{
					slog.String("id", "xxxx"),
					slog.Group("metadata", slog.String("label", "test")),
				}),
			)

			slogLogger.Log(ctx, types.LevelTrace, "trace record with no attributes")

			if test.slogLevel <= types.LevelTrace {
				check(
					"trace",
					`"base:id":"xxxx","base:metadata:label":"test",`+
						`"message":"trace record with no attributes"`,
				)
			} else {
				check("", ``)
			}

			slogLogger.Debug("debug record with a single attribute", "str", "value")

			if test.slogLevel <= slog.LevelDebug {
				check(
					"debug",
					`"base:id":"xxxx","base:metadata:label":"test",`+
						`"base:str":"value","message":"debug record with a single attribute"`,
				)
			} else {
				check("", ``)
			}

			slogLogger.Info("info record with a single group attribute",
				slog.Group("group", slog.String("str", "value"), slog.Int("int", 5)))

			if test.slogLevel <= slog.LevelInfo {
				check(
					"info",
					`"base:group:int":5,"base:group:str":"value","base:id":"xxxx",`+
						`"base:metadata:label":"test","message":"info record with a single group attribute"`,
				)
			} else {
				check("", ``)
			}

			slogLogger.Warn("warn record with more attributes", "str", "value", "int", 2)

			if test.slogLevel <= slog.LevelWarn {
				check(
					"warn",
					`"base:id":"xxxx","base:int":2,"base:metadata:label":"test",`+
						`"base:str":"value","message":"warn record with more attributes"`,
				)
			} else {
				check("", ``)
			}

			slogLogger.Error("error record with a nested groups",
				slog.Group("group1", slog.String("str1", "value1"), slog.Int("int1", 5)),
				slog.Group("group2", slog.String("str2", "value2"), slog.Group("group3", slog.Int("int2", 10))),
			)

			if test.slogLevel <= slog.LevelError {
				check(
					"error",
					`"base:group1:int1":5,"base:group1:str1":"value1","base:group2:group3:int2":10,`+
						`"base:group2:str2":"value2","base:id":"xxxx","base:metadata:label":"test",`+
						`"message":"error record with a nested groups"`,
				)
			} else {
				check("", ``)
			}
		}
	})
}

func checkLogOutput(t *testing.T, got, wantRegexp string) {
	t.Helper()

	got = clean(got)
	wantRegexp = "^" + wantRegexp + "$"

	matched, err := regexp.MatchString(wantRegexp, got)
	if err != nil {
		t.Fatal(err)
	}

	if !matched {
		t.Errorf("\ngot %s\nwant %s", got, wantRegexp)
	}
}

func clean(s string) string {
	if len(s) > 0 && s[len(s)-1] == '\n' {
		s = s[:len(s)-1]
	}

	return strings.ReplaceAll(s, "\n", "~")
}

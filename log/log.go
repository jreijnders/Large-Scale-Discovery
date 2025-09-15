/*
* Large-Scale Discovery, a network scanning solution for information gathering in large IT/OT network environments.
*
* Copyright (c) Siemens AG, 2016-2025.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package log

import (
	"fmt"
	"github.com/siemens/ZapSmtp"
	"go.uber.org/multierr"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
	"io"
	"os"
	"sync"
)

var globalLogger Logger
var initOnce sync.Once

type Logger interface {
	io.Closer
	Sync() error

	Tagged(string) Logger
	Debugf(template string, args ...interface{})
	Infof(template string, args ...interface{})
	Warningf(template string, args ...interface{})
	Errorf(template string, args ...interface{})
}

// GetLogger returns the same single global logger instance to all callers
func GetLogger() Logger {
	return globalLogger
}

// InitGlobalLogger initializes a GLOBAL logger based on a given configuration struct
func InitGlobalLogger(conf Settings) (Logger, error) {

	var err error
	initOnce.Do(func() {
		c := make([]zapcore.Core, 0, 3)
		var closeFns []func() error

		// Create the different cores depending on the config. Anonymous function so we can handle errors better
		err = func() error {
			if conf.Console != nil && conf.Console.Enabled {
				core, errCore := newConsoleCore(conf.Console)
				if errCore != nil {
					return errCore
				}
				c = append(c, core)
			}

			if conf.File != nil && conf.File.Enabled {
				core, closeCoreFn, errCore := newFileCore(conf.File)
				if errCore != nil {
					return errCore
				}
				c = append(c, core)
				closeFns = append(closeFns, closeCoreFn)
			}

			if conf.Smtp != nil && conf.Smtp.Enabled {
				core, closeCoreFn, errCore := newSmtpCore(conf.Smtp)
				if errCore != nil {
					return errCore
				}
				c = append(c, core)
				closeFns = append(closeFns, closeCoreFn)
			}

			return nil
		}()

		if err != nil {
			for _, f := range closeFns {
				errF := f()
				if errF != nil {
					err = multierr.Append(err, errF)
				}
			}
			return
		}

		// Tee all the cores together
		tee := zapcore.NewTee(c...)

		// Set the global logger
		globalLogger = NewZapLogger(zap.New(tee).Sugar(), closeFns...)
	})

	// Return global logger
	return globalLogger, err
}

// CloseGlobalLogger will call the Close method of the global logger
func CloseGlobalLogger() error {
	if globalLogger != nil {
		return globalLogger.Close()
	}

	return nil
}

// StdoutWriter wraps os.Stdout implementing the zapcore.WriteSyncer.
// While os.Stdout already supports this interface, calling Sync() on it causes an error on Windows
// ("sync /dev/stdout: The handle is invalid."). Since Sync() isn't needed for Stdout, this wrapper
// ignores Sync() calls to avoid the error.
type StdoutWriter struct {
	file *os.File
}

func (w StdoutWriter) Write(p []byte) (n int, err error) {
	return w.file.Write(p)
}
func (w StdoutWriter) Sync() error {
	return nil
}

// InitConsoleCore creates a new core for logging to the console according to the provided configuration
func newConsoleCore(conf *ConsoleHandler) (zapcore.Core, error) {

	// Prepare WriteSyncer with Stdout
	w := StdoutWriter{os.Stdout}

	// Patch WriteSyncer to restrict concurrent access
	ws := zapcore.Lock(w)

	// Create the encoder. We prefer to have a custom Name (/Tag) Encoder
	encConf := zap.NewDevelopmentEncoderConfig()
	encConf.EncodeName = NameEncoder
	encConf.EncodeTime = TimeEncoder
	enc := zapcore.NewConsoleEncoder(encConf)

	// Return core
	return zapcore.NewCore(enc, ws, conf.Level), nil
}

// InitFileCore creates a new core for logging to a file according to the provided configuration
func newFileCore(conf *FileHandler) (zapcore.Core, func() error, error) {

	// Prepare lumberjack logger taking care of file rotation
	w := &lumberjack.Logger{
		Filename:   conf.Path,
		MaxSize:    conf.SizeMb, // megabytes
		MaxBackups: conf.History,
		MaxAge:     28, // days
	}

	// Patch lumberjack to add Noop Sync in order to satisfy the WriteSyncer interface
	ws := zapcore.AddSync(w)

	// Create the encoder. We prefer to have a custom Name (/Tag) Encoder
	encConf := zap.NewDevelopmentEncoderConfig()
	encConf.EncodeName = NameEncoder
	encConf.EncodeTime = TimeEncoder
	enc := zapcore.NewConsoleEncoder(encConf)

	// Return core and close function
	return zapcore.NewCore(enc, ws, conf.Level), w.Close, nil
}

func newSmtpCore(conf *SmtpHandler) (zapcore.Core, func() error, error) {

	// Use a sink as it performs a bit better
	ws, fnCleanup, errWs := ZapSmtp.NewSmtpSyncer(
		conf.Connector.Server,
		conf.Connector.Port,
		conf.Connector.Username,
		conf.Connector.Password,

		conf.Connector.Subject,
		conf.Connector.Sender,
		conf.Connector.Recipients,

		conf.Connector.OpensslPath,
		conf.Connector.SignatureCertPath,
		conf.Connector.SignatureKeyPath,
		conf.Connector.EncryptionCertPaths,
	)
	if errWs != nil {
		return nil, nil, fmt.Errorf("could not initialize SMTP writeSyncer: %s", errWs)
	}

	// Create the encoder. We prefer to have a custom Name (/Tag) Encoder
	encConf := zap.NewDevelopmentEncoderConfig()
	encConf.EncodeName = NameEncoder
	encConf.EncodeTime = TimeEncoder
	enc := zapcore.NewConsoleEncoder(encConf)

	core, errCore := ZapSmtp.NewDelayedCore(conf.Level, enc, ws, conf.LevelPriority, conf.Delay, conf.DelayPriority)
	if errCore != nil {
		_ = fnCleanup()
		return nil, nil, fmt.Errorf("could not initialize delayed core: %s", errCore)
	}

	// Return core and cleanup function
	return core, fnCleanup, nil
}

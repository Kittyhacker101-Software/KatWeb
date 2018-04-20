// KatWeb by kittyhacker101 - GZIP Compression Middleware
package main

import (
	"github.com/klauspost/compress/gzip"
	"io"
	"net/http"
	"strings"
	"sync"
)

var zippers = sync.Pool{New: func() interface{} {
	var gz *gzip.Writer

	switch conf.Pef.GZ {
	case 3:
		// Highest compression level
		gz, _ = gzip.NewWriterLevel(nil, gzip.BestCompression)
	case 1:
		// Speed-optimized compression
		gz, _ = gzip.NewWriterLevel(nil, gzip.ConstantCompression)
	default:
		// Mix between speed and compression
		gz, _ = gzip.NewWriterLevel(nil, 4)
	}

	return gz
}}

// MakeGzipHandler creates a wrapper for an http.Handler with Gzip compression.
func MakeGzipHandler(funct http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		//TODO : Send previously compressed responses
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") || conf.Pef.GZ == 0 || strings.Contains(r.Header.Get("Upgrade"), "websocket") {
			funct(w, r)
			return
		}

		w.Header().Set("Content-Encoding", "gzip")

		gz := zippers.Get().(*gzip.Writer)
		gz.Reset(w)

		funct(gzipResponseWriter{Writer: gz, ResponseWriter: w}, r)

		gz.Close()
		zippers.Put(gz)
	}
}

type gzipResponseWriter struct {
	io.Writer
	http.ResponseWriter
}

func (w gzipResponseWriter) Write(b []byte) (int, error) {
	return w.Writer.Write(b)
}

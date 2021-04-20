package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"regexp"

	"github.com/linead/docker-socket-firewall/opa"

	"github.com/docker/go-connections/sockets"
	"github.com/h2non/filetype"
	"github.com/h2non/filetype/matchers"
	log "github.com/sirupsen/logrus"
	"github.com/xi2/xz"
)

var opaHandler opa.DockerHandler
var targetSocket string
var gitInfo string
var doPing *bool

/*
	Reverse Proxy Logic
*/

// For a given url request, connect to targetSocket with a http client pass the req and
func serveReverseProxy(w http.ResponseWriter, req *http.Request) {
	transport := new(http.Transport)
	sockets.ConfigureTransport(transport, "unix", targetSocket)
	client := &http.Client{
		Transport: transport,
	}

	prettyReq, _ := byteDent(httputil.DumpRequest(req, false))
	req.Proto = "http"
	req.URL.Scheme = "http"
	req.URL.Host = targetSocket
	req.RequestURI = ""
	req.Close = true

	if req.Header.Get("Connection") == "Upgrade" {
		if req.Header.Get("Upgrade") != "tcp" && req.Header.Get("Upgrade") != "h2c" {
			http.Error(w, "Unsupported upgrade protocol: "+req.Header.Get("Protocol"), http.StatusInternalServerError)
			return
		}
		log.Tracef("%s: REQ%s", req.Header.Get("Upgrade"), prettyReq)
		hijack(req, w)
	} else {
		log.Tracef("http: REQ%s", prettyReq)
		resp, err := client.Do(req)
		prettyResp, _ := byteDent(httputil.DumpResponse(resp, false))
		log.Tracef("http: RESP%s", prettyResp)

		if err != nil {
			log.Error(err)
			return
		}

		defer resp.Body.Close()

		copyHeader(w.Header(), resp.Header)

		//If we're looking at a raw stream and we're not sending a value fo TE golang tries
		//to chunk the response, which can break clients.
		if resp.Header.Get("Content-Type") == "application/vnd.docker.raw-stream" {
			if resp.Header.Get("Transfer-Encoding") == "" {
				w.Header().Set("Transfer-Encoding", "identity")
			}
		}
		w.WriteHeader(resp.StatusCode)

		flushResponse(w)
		copyBuffer(w, resp.Body)
	}
}

// Indent a bytearray for pretty printing
func byteDent(src []byte, err error) ([]byte, error) {
	dest := make([]byte, 0, 10000)
	if err == nil {
		dest = append(dest, "\n    "...)
		for _, s := range src {
			if s == '\n' {
				dest = append(dest, "\n    "...)
			} else {
				dest = append(dest, s)
			}
		}
	} else {
		copy(dest, src)
	}
	return dest, err
}

//TODO: hikack doesnt watch the requests once /session is up - need to enhance so it can
// use http client library call to establish connection then hijack it and set up goroutines to async handle send and receive
func hijack(req *http.Request, w http.ResponseWriter) {
	inConn, err := net.Dial("unix", targetSocket)

	if err != nil {
		log.Warnf("hijack: Error in connection %v", err)
	}

	// they really dont want us to be using NewClientConn here - but the current technique here is to establish the connection
	// so it can then be hijacked.
	clientconn := httputil.NewClientConn(inConn, nil)

	// Server hijacks the connection, error 'connection closed' expected
	resp, err := clientconn.Do(req)
	if err != httputil.ErrPersistEOF {
		if err != nil {
			log.Errorf("hijack: error upgrading: %v", err)
		}
		if resp.StatusCode != http.StatusSwitchingProtocols {
			resp.Body.Close()
			log.Errorf("hijack: unable to upgrade to %s, received %d", "tcp", resp.StatusCode)
		}
	}
	log.Tracef("hijack: NewClientConn err=%v", err)

	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	flushResponse(w)

	c, br := clientconn.Hijack()

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "webserver doesn't support hijacking", http.StatusInternalServerError)
		log.Errorf("webserver doesn't support hijacking: %v", ok)
		return
	}
	outConn, _, err := hj.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Errorf("hijack: outConn err=%v", err)
		return
	}

	if br.Buffered() > 0 {
		log.Tracef("Found buffered bytes")
		var bs = make([]byte, br.Buffered())
		br.Read(bs)
		outConn.Write(bs)
	}

	errClient := make(chan error, 1)
	errBackend := make(chan error, 1)

	streamFn := func(dst, src net.Conn, errc chan error, desc string) {
		log.Tracef("hijack: %s Streaming connections", desc)
		written, err := copyBuffer(dst, src)
		log.Tracef("hijack: %s wrote %v, err: %v", desc, written, err)
		errc <- err
	}

	go streamFn(outConn, c, errClient, "docker -> client")
	go streamFn(c, outConn, errBackend, "client -> docker")

	select {
	case err = <-errClient:
		if err != nil {
			log.Errorf("hijack: Error when copying from docker to client: %v", err)
		} else {
			log.Trace("hijack: client closed connection")
		}
	case err = <-errBackend:
		if err != nil {
			log.Debugf("hijack: Error when copying from docker to client: %v", err)
		} else {
			log.Debug("hijack: backend closed connection")
		}
	}

	c.Close()
	outConn.Close()
	clientconn.Close()
	inConn.Close()
}

// when streaming - read all of buffer from src io.Reader and write to dst io.Writer
func copyBuffer(dst io.Writer, src io.Reader) (int64, error) {
	var buf = make([]byte, 100)
	var written int64
	for {
		nr, rerr := src.Read(buf)
		if rerr != nil && rerr != io.EOF && rerr != context.Canceled {
			log.Errorf("copyBuffer: read error during body copy: %v", rerr)
		}
		if nr > 0 {
			nw, werr := dst.Write(buf[:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if werr != nil {
				return written, werr
			}
			if nr != nw {
				return written, io.ErrShortWrite
			}
			flushResponse(dst)
		}
		if rerr != nil {
			if rerr == io.EOF {
				rerr = nil
			}
			return written, rerr
		}
	}
}

// clone all the http headers in src request to dst request
func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// sneak peek 262 bytes from a build request body to figure out what kind of tar compression
// it is and then try and parse from it the path to the Dockerfile
// if a Dockerfile path can be found then feed it to opa validator.
// return true only if a Dockerfile is found and opa determmines valid.
// BUG: does not handle build requests with no body gracefully.
func verifyBuildInstruction(req *http.Request) (bool, error) {
	//preserve original request if we want to still send it (Dockerfile is clean)
	var buf bytes.Buffer
	b := req.Body
	var err error
	var valid = true

	if _, err = buf.ReadFrom(b); err != nil {
		return false, err
	}

	if err = b.Close(); err != nil {
		return false, err
	}

	b1, b2 := bufio.NewReader(&buf), ioutil.NopCloser(bytes.NewReader(buf.Bytes()))

	head, err := b1.Peek(262)
	if err != nil {
		log.Errorf("peek returned %d bytes before %v", len(head), err)
	}

	if len(head) > 0 {
		var tr *tar.Reader

		if filetype.IsType(head, matchers.TypeGz) {
			gzipReader, _ := gzip.NewReader(b1)
			tr = tar.NewReader(gzipReader)
		} else if filetype.IsType(head, matchers.TypeBz2) {
			bz2Reader := bzip2.NewReader(b1)
			tr = tar.NewReader(bz2Reader)
		} else if filetype.IsType(head, matchers.TypeXz) {
			xzReader, _ := xz.NewReader(b1, 0)
			tr = tar.NewReader(xzReader)
		} else if filetype.IsType(head, matchers.TypeTar) {
			tr = tar.NewReader(b1)
		} else {
			log.Tracef("filetype tar reader not handled: %v", head)
		}

		dockerfileLoc := req.URL.Query().Get("dockerfile")

		if dockerfileLoc == "" {
			dockerfileLoc = "Dockerfile"
		}
		log.Tracef("Dockerfile name: %s", dockerfileLoc)

		for {
			hdr, err := tr.Next()
			if err == io.EOF {
				break // End of archive
			}
			if err != nil {
				log.Error(err)
			}
			if hdr.Name == dockerfileLoc {
				df, _ := ioutil.ReadAll(tr)
				log.Tracef("Dockerfile size: %d", len(df))
				valid, err = opaHandler.ValidateDockerFile(req, string(df))
				if err != nil {
					log.Error(err)
				}
			}
		}
	}
	if valid {
		req.Body = b2
	}

	return valid, nil
}

// Given a uri - figure out if it a request or a build command and send it to the appropriate validator. If valid then pass
// request to the backend. if not valid return http refusal.
func handleRequestAndRedirect(res http.ResponseWriter, req *http.Request) {

	var err error
	allowed := false

	isPing, _ := regexp.MatchString("^/_ping$", req.URL.Path)
	isSession, _ := regexp.MatchString("^(/v[\\d\\.]+)?/session$", req.URL.Path)
	isBuild, _ := regexp.MatchString("^(/v[\\d\\.]+)?/build$", req.URL.Path)
	if isPing {
		allowed = *doPing
	} else if isSession {
		allowed = true
	} else if isBuild {
		allowed, err = verifyBuildInstruction(req)
	} else {
		allowed, err = opaHandler.ValidateRequest(req)
	}

	if err != nil {
		errMsg := fmt.Sprintf("Validation failure: err=%v", err)
		log.WithFields(log.Fields{
			"policy": "DENIED",
			"reason": errMsg,
		}).Error(req.URL.Path)
		http.Error(res, errMsg, http.StatusInternalServerError)
	} else if allowed {
		log.WithFields(log.Fields{
			"policy": "PERMIT",
		}).Debug(req.URL.Path)

		serveReverseProxy(res, req)
	} else {
		http.Error(res, "Authorization denied", http.StatusUnavailableForLegalReasons)
		log.WithFields(log.Fields{
			"policy": "DENIED",
		}).Error(req.URL.Path)
	}
}

// open publicly RW named pipe and start http server on it. this is the named pipe the docker client
// commands connect to
func listenAndServe(sockPath string) error {
	log.Tracef("initialising named pipe: %s", sockPath)
	http.HandleFunc("/", handleRequestAndRedirect)
	l, err := net.Listen("unix", sockPath)
	if err != nil {
		return err
	}
	err = os.Chmod(sockPath, 0777)
	if err != nil {
		return err
	}

	log.Tracef("entering http listener on socket at: %s", sockPath)
	return http.Serve(l, nil)
}

// flushResponse: flush http response write buffer
func flushResponse(w io.Writer) {
	flusher, ok := w.(http.Flusher)
	if ok {
		flusher.Flush()
	}
}

// setupLogFile: if -log cmdline arg is asserted then divert logging to nominated file - handle size limit by rolling away old log
//               to .0 if it is over 10Mb.
func setupLogFile(logPath string) {
	oPath := logPath + ".0"

	logFile := filepath.Clean(logPath)
	oFile := filepath.Clean(oPath)

	if fInfo, err := os.Stat(logFile); err == nil {
		if fInfo.Size() > 10*1024*1024 {
			//rollover the logfile before opening
			log.Infof("logfile %s > 10Mib, rotating to %s", logFile, oFile)
			if err := os.Rename(logFile, oFile); err != nil {
				log.Error(err)
			}
		}
	}

	f, err := os.OpenFile(logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		log.WithFields(log.Fields{
			"err":     err,
			"logfile": logFile,
		}).Fatal("error opening logdest")
	}

	log.SetFormatter(&log.JSONFormatter{})
	log.SetOutput(f)
}

// Main Entrypoint
func main() {

	var hostSocket string
	var policyDir string
	var logFile string

	flag.StringVar(&targetSocket, "target", "docker.sock", "The docker socket to connect to")
	flag.StringVar(&hostSocket, "host", "docker-proxy.sock", "The docker socket to listen on")
	flag.StringVar(&policyDir, "policyDir", "testpolicy", "The directory containing the OPA policies")
	flag.StringVar(&logFile, "log", "STDOUT", "path to divert stdout to")
	printUsage := flag.Bool("usage", false, "Print usage information")
	verbose := flag.Bool("verbose", false, "Print debug level logging")
	trace := flag.Bool("trace", false, "Print trace level logging")
	version := flag.Bool("version", false, "only show version")
	doPing = flag.Bool("doping", false, "unblock pings")

	flag.Parse()

	//show version and exit cleanly
	if *version {
		fmt.Printf("%s\n", gitInfo)
		os.Exit(0)
	}

	if *printUsage {
		flag.Usage()
		os.Exit(0)
	}

	if logFile != "STDOUT" {
		log.WithFields(log.Fields{
			"logfile": logFile,
		}).Info("docker-socket-firewall started")

		setupLogFile(logFile)
	} else {
		log.SetFormatter(&log.TextFormatter{
			DisableLevelTruncation: true,
			FullTimestamp:          true,
			TimestampFormat:        "15:04:05.000000",
		})
	}

	// have a way for admin to turn on tracing by touching this file
	if _, err := os.Stat(filepath.Clean("/var/run/docker-socket-firewall.debug")); err == nil {
		log.SetLevel(log.DebugLevel)
	}
	if _, err := os.Stat(filepath.Clean("/var/run/docker-socket-firewall.trace")); err == nil {
		log.SetLevel(log.TraceLevel)
	}
	if *verbose {
		log.SetLevel(log.DebugLevel)
	}
	if *trace {
		log.SetLevel(log.TraceLevel)
	}

	// clean up old socket in case its a link
	// TODO: some error handling would be nice
	os.Remove(hostSocket)

	proxyPolicyFile := filepath.Join(policyDir, "authz.rego")
	buildPolicyFile := filepath.Join(policyDir, "build.rego")

	opaHandler = &opa.DockerOpaHandler{
		ProxyPolicyFile:      proxyPolicyFile,
		DockerfilePolicyFile: buildPolicyFile}

	log.WithFields(log.Fields{
		"revision":        gitInfo,
		"targetSocket":    targetSocket,
		"hostSocket":      hostSocket,
		"proxyPolicyFile": proxyPolicyFile,
		"buildPolicyFile": buildPolicyFile,
	}).Info("docker-socket-firewall init")

	// validate target socket
	if tInfo, err := os.Lstat(targetSocket); err == nil {
		if tInfo.Mode()&os.ModeSymlink != 0 {
			if tPipe, err := os.Readlink(targetSocket); err == nil {
				log.Infof("%s is symlink to %s", targetSocket, tPipe)
			} else {
				log.Infof("%s is not symlink", targetSocket)
			}
		}
	} else {
		log.Warn(err)
	}

	// start server
	if err := listenAndServe(hostSocket); err != nil {
		log.WithFields(log.Fields{
			"err":        err,
			"hostSocket": hostSocket,
		}).Fatal("error opening host named pipe")

	}
}

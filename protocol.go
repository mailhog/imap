package imap

// https://www.ietf.org/rfc/rfc3501.txt

import (
	"log"
	"strings"
)

// Command is a struct representing an SMTP command (verb + arguments)
type Command struct {
	tag     string
	command string
	args    string
	orig    string
}

// ParseCommand returns a Command from the line string
func ParseCommand(line string) *Command {
	words := strings.Split(line, " ")
	tag := strings.ToUpper(words[0])
	command := strings.ToUpper(words[1])
	args := strings.Join(words[2:len(words)], " ")

	return &Command{
		tag:     tag,
		command: command,
		args:    args,
		orig:    line,
	}
}

// Protocol is a state machine representing an SMTP session
type Protocol struct {
	TLSPending  bool
	TLSUpgraded bool

	State State

	Hostname string
	Ident    string
	Revision string

	MaximumLineLength int

	// LogHandler is called for each log message. If nil, log messages will
	// be output using log.Printf instead.
	LogHandler func(message string, args ...interface{})
	// ValidateAuthenticationhandler should return true if the authentication
	// parameters are valid, otherwise false. If nil, all authentication
	// attempts will be accepted.
	ValidateAuthenticationHandler func(mechanism string, args ...string) (errorResponse *Response, ok bool)
	// TLSHandler is called when a STARTTLS command is received.
	//
	// It should acknowledge the TLS request and set ok to true.
	// It should also return a callback which will be invoked after the Response is
	// sent. E.g., a TCP connection can only perform the upgrade after sending the Response
	//
	// Once the upgrade is complete, invoke the done function (e.g., from the returned callback)
	//
	// If TLS upgrade isn't possible, return an errorResponse and set ok to false.
	TLSHandler func(done func(ok bool)) (errorResponse *Response, callback func(), ok bool)

	// GetAuthenticationMechanismsHandler should return an array of strings
	// listing accepted authentication mechanisms
	GetAuthenticationMechanismsHandler func() []string

	// RequireTLS controls whether TLS is required for a connection before other
	// commands can be issued, applied at the protocol layer.
	RequireTLS bool
}

// NewProtocol returns a new SMTP state machine in INVALID state
// handler is called when a message is received and should return a message ID
func NewProtocol() *Protocol {
	p := &Protocol{
		Hostname:          "mailhog.example",
		Ident:             "MailHog",
		Revision:          "IMAP4rev1",
		State:             INVALID,
		MaximumLineLength: 8000,
	}
	return p
}

func (proto *Protocol) logf(message string, args ...interface{}) {
	message = strings.Join([]string{"[PROTO: %s]", message}, " ")
	args = append([]interface{}{StateMap[proto.State]}, args...)

	if proto.LogHandler != nil {
		proto.LogHandler(message, args...)
	} else {
		log.Printf(message, args...)
	}
}

// Start begins an IMAP conversation with an OK response, placing the state
// machine in PREAUTH state.
func (proto *Protocol) Start() *Response {
	proto.logf("Started session, switching to PREAUTH state")
	proto.State = PREAUTH
	return ResponseIdent(proto.Revision, proto.Hostname, proto.Ident)
}

// Parse parses a line string and returns any remaining line string
// and a Response, if a command was found. Parse does nothing until a
// new line is found.
// - TODO decide whether to move this to a buffer inside Protocol
//   sort of like it this way, since it gives control back to the caller
func (proto *Protocol) Parse(line string) (string, *Response) {
	var Response *Response

	if !strings.Contains(line, "\r\n") {
		return line, Response
	}

	parts := strings.SplitN(line, "\r\n", 2)
	line = parts[1]

	if proto.MaximumLineLength > -1 {
		if len(parts[0]) > proto.MaximumLineLength {
			return line, ResponseLineTooLong("*") // FIXME should be tagged
		}
	}

	Response = proto.ProcessCommand(parts[0])

	return line, Response
}

// ProcessCommand processes a line of text as a command
// It expects the line string to be a properly formed SMTP verb and arguments
func (proto *Protocol) ProcessCommand(line string) (Response *Response) {
	line = strings.Trim(line, "\r\n")
	proto.logf("Processing line: %s", line)

	words := strings.Split(line, " ")
	command := strings.ToUpper(words[0])
	args := strings.Join(words[1:len(words)], " ")
	proto.logf("In state %d, got command '%s', args '%s'", proto.State, command, args)

	cmd := ParseCommand(strings.TrimSuffix(line, "\r\n"))
	return proto.Command(cmd)
}

// Command applies an SMTP verb and arguments to the state machine
func (proto *Protocol) Command(command *Command) (Response *Response) {
	switch {
	case proto.TLSPending && !proto.TLSUpgraded:
		proto.logf("Got command before TLS upgrade complete")
		// FIXME what to do?
		return ResponseBye()
	default:
		proto.logf("Command not recognised")
		return ResponseUnrecognisedCommand("*") // FIXME should be tagged
	}
}

// STARTTLS creates a Response to a STARTTLS command
func (proto *Protocol) STARTTLS(args string) (Response *Response) {
	if proto.TLSUpgraded {
		return ResponseUnrecognisedCommand("*") // FIXME should be tagged
	}

	if proto.TLSHandler == nil {
		proto.logf("tls handler not found")
		return ResponseUnrecognisedCommand("*") // FIXME should be tagged
	}

	if len(args) > 0 {
		return ResponseSyntaxError("no parameters allowed")
	}

	r, callback, ok := proto.TLSHandler(func(ok bool) {
		proto.TLSUpgraded = ok
		proto.TLSPending = ok
		if ok {
			proto.State = PREAUTH
		}
	})
	if !ok {
		return r
	}

	proto.TLSPending = true
	return ResponseReadyToStartTLS("*", callback) // FIXME should be tagged
}

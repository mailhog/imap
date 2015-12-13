package imap

// https://www.ietf.org/rfc/rfc3501.txt

import (
	"log"
	"strings"

	"github.com/mailhog/backends/auth"
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
	if len(words) < 2 {
		// FIXME error
		return nil
	}

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
	readIntercept func(l string)

	TLSPending  bool
	TLSUpgraded bool

	State     State
	Responses chan *Response

	Hostname string
	Ident    string
	Revision string

	MaximumLineLength int

	Capabilities map[string]Capability

	// LogHandler is called for each log message. If nil, log messages will
	// be output using log.Printf instead.
	LogHandler func(message string, args ...interface{})
	// ValidateAuthenticationhandler should return true if the authentication
	// parameters are valid, otherwise false. If nil, all authentication
	// attempts will be accepted.
	ValidateAuthenticationHandler func(mechanism string, args ...string) (ok bool)
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

// Capability represents an IMAP capability
type Capability interface {
	Name() string
	Available(p *Protocol) bool
}

// GenericCapability represents a generic IMAP4rev1 capability
type GenericCapability struct {
	name       string
	requireTLS bool
	skipIfTLS  bool
}

// Name implements Capability.Name
func (gc *GenericCapability) Name() string {
	return gc.name
}

// Available implements Capability.Available
func (gc *GenericCapability) Available(p *Protocol) bool {
	if gc.requireTLS && !p.TLSUpgraded {
		return false
	}
	if gc.skipIfTLS && p.TLSUpgraded {
		return false
	}
	return true
}

// NewProtocol returns a new SMTP state machine in INVALID state
func NewProtocol(responses chan *Response) *Protocol {
	p := &Protocol{
		Hostname:          "mailhog.example",
		Ident:             "MailHog",
		Revision:          "IMAP4rev1",
		State:             INVALID,
		MaximumLineLength: 8000,
		Responses:         responses,

		Capabilities: map[string]Capability{
			"IMAP4rev1":     &GenericCapability{name: "IMAP4rev1"},
			"STARTTLS":      &GenericCapability{name: "STARTTLS", skipIfTLS: true},
			"LOGINDISABLED": &GenericCapability{name: "IMAP4rev1"},
			"AUTH=PLAIN":    &GenericCapability{name: "AUTH=PLAIN", requireTLS: true},
		},
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
func (proto *Protocol) Parse(line string) string {
	if !strings.Contains(line, "\r\n") {
		return line
	}

	parts := strings.SplitN(line, "\r\n", 2)
	line = parts[1]

	if proto.MaximumLineLength > -1 {
		if len(parts[0]) > proto.MaximumLineLength {
			proto.Responses <- ResponseLineTooLong("*") // FIXME should be tagged
			return line
		}
	}

	if proto.readIntercept != nil {
		proto.readIntercept(parts[0])
	} else {
		proto.ProcessCommand(parts[0])
	}

	return line
}

// ProcessCommand processes a line of text as a command
// It expects the line string to be a properly formed SMTP verb and arguments
func (proto *Protocol) ProcessCommand(line string) {
	line = strings.Trim(line, "\r\n")
	proto.logf("Processing line: %s", line)

	words := strings.Split(line, " ")
	if len(words) < 2 {
		proto.logf("Unable to parse line")
		t := "*"
		if len(words) > 0 {
			t = words[0]
		}
		proto.Responses <- ResponseUnrecognisedCommand(t)
		return
	}

	tag := words[0]
	command := strings.ToUpper(words[1])
	args := strings.Join(words[2:len(words)], " ")
	proto.logf("In state %d, got tag '%s' for command '%s', args '%s'", proto.State, tag, command, args)

	cmd := ParseCommand(strings.TrimSuffix(line, "\r\n"))
	proto.Command(cmd)
}

// Command applies an SMTP verb and arguments to the state machine
func (proto *Protocol) Command(command *Command) {
	switch {
	case proto.TLSPending && !proto.TLSUpgraded:
		proto.logf("Got command before TLS upgrade complete")
		proto.Responses <- &Response{"*", Status(ResponseBYE), nil, "", nil}
		proto.State = LOGOUT
		return
	case "CAPABILITY" == command.command:
		proto.CAPABILITY(command)
		return
	case "NOOP" == command.command:
		proto.Responses <- &Response{command.tag, Status(ResponseOK), nil, "", nil}
		return
	case "LOGOUT" == command.command:
		proto.Responses <- &Response{"*", Status(ResponseBYE), nil, "", nil}
		proto.Responses <- &Response{command.tag, Status(ResponseOK), nil, "", nil}
		proto.State = LOGOUT
		return
	case PREAUTH == proto.State:
		switch command.command {
		case "STARTTLS":
			proto.STARTTLS(command)
			return
		case "AUTHENTICATE":
			proto.AUTHENTICATE(command)
			return
		case "LOGIN":
			proto.Responses <- &Response{command.tag, Status(ResponseBAD), nil, "", nil}
			return
		}
		proto.logf("command not found in PREAUTH state")
	case AUTH == proto.State:
		switch command.command {
		case "SELECT":
		case "EXAMINE":
		case "CREATE":
		case "DELETE":
		case "RENAME":
		case "SUBSCRIBE":
		case "UNSUBSCRIBE":
		case "LIST":
			// FIXME hook
			proto.Responses <- &Response{"*", nil, nil, `LIST (\Noselect) "/" ""`, nil}
			proto.Responses <- &Response{command.tag, Status(ResponseOK), nil, "", nil}
			return
		case "LSUB":
		case "STATUS":
		case "APPEND":
		}
		proto.logf("command not found in AUTH state")
	case SELECTED == proto.State:
		switch command.command {
		case "CHECK":
		case "CLOSE":
		case "EXPUNGE":
		case "SEARCH":
		case "FETCH":
		case "STORE":
		case "COPY":
		case "UID":
		}
		proto.logf("command not found in PREAUTH state")
	}

	proto.logf("Command not recognised")
	proto.Responses <- ResponseUnrecognisedCommand("*") // FIXME should be tagged
}

// STARTTLS creates a Response to a STARTTLS command
func (proto *Protocol) STARTTLS(command *Command) {
	if proto.TLSUpgraded {
		proto.Responses <- ResponseUnrecognisedCommand(command.tag)
		return
	}

	if proto.TLSHandler == nil {
		proto.logf("tls handler not found")
		proto.Responses <- ResponseUnrecognisedCommand(command.tag)
		return
	}

	if len(command.args) > 0 {
		proto.Responses <- ResponseSyntaxError("no parameters allowed")
		return
	}

	r, callback, ok := proto.TLSHandler(func(ok bool) {
		proto.TLSUpgraded = ok
		proto.TLSPending = ok
		if ok {
			proto.State = PREAUTH
		}
	})
	if !ok {
		proto.Responses <- r
		return
	}

	proto.TLSPending = true
	proto.Responses <- ResponseReadyToStartTLS(command.tag, callback)
	return
}

// CAPABILITY implements RFC3501 CAPABILITY command
func (proto *Protocol) CAPABILITY(cmd *Command) {
	// Return untagged CAPABILITY
	var capabilities []string
	for k, v := range proto.Capabilities {
		if !v.Available(proto) {
			continue
		}
		capabilities = append(capabilities, k)
	}
	proto.Responses <- &Response{"*", nil, Code(CAPABILITY), strings.Join(capabilities, " "), nil}

	// Return tagged OK
	proto.Responses <- &Response{cmd.tag, Status(ResponseOK), nil, "", nil}
}

// AUTHENTICATE implements RFC3501 AUTHENTICATE command
func (proto *Protocol) AUTHENTICATE(command *Command) {
	args := strings.Split(command.args, " ")

	if len(args) < 1 {
		// FIXME what error?
		proto.Responses <- ResponseUnrecognisedCommand(command.tag)
		return
	}

	switch strings.ToUpper(args[0]) {
	case "PLAIN":
		if len(args) > 1 {
			// Do auth now
			return
		}
		proto.readIntercept = func(l string) {
			proto.readIntercept = nil
			user, pass, err := auth.DecodePLAIN(l)
			if err != nil {
				// FIXME what error?
				proto.Responses <- ResponseUnrecognisedCommand(command.tag)
				return
			}
			if ok := proto.ValidateAuthenticationHandler("PLAIN", user, pass); !ok {
				// FIXME what error?
				proto.Responses <- ResponseUnrecognisedCommand(command.tag)
				return
			}
			// OK
			proto.State = AUTH
			proto.Responses <- &Response{command.tag, Status(ResponseOK), nil, "", nil}
			return
		}
		proto.Responses <- &Response{"+", nil, nil, "", nil}
		return
	}

	// FIXME what error?
	proto.Responses <- ResponseUnrecognisedCommand(command.tag)
}

// SELECT implements RFC3501 SELECT command
func (proto *Protocol) SELECT(command *Command) {

}

// CREATE implements RFC3501 CREATE command
func (proto *Protocol) CREATE(command *Command) {

}

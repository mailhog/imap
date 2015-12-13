package imap

// https://www.ietf.org/rfc/rfc3501.txt

// Response is a struct representing an IMAP response
type Response struct {
	Tag    string
	Status *ResponseStatus
	Code   *ResponseCode
	Text   string
	Done   func()
}

// ResponseStatus represents an IMAP response status
type ResponseStatus int

// ResponseCode represents an IMAP response code
type ResponseCode string

const (
	// ResponseOK represents an OK response
	ResponseOK = ResponseStatus(iota)
	// ResponseNO represents a NO response
	ResponseNO
	// ResponseBAD represents a BAD response
	ResponseBAD
	// ResponsePREAUTH represents a PREAUTH response
	ResponsePREAUTH
	// ResponseBYE represents a BYE response
	ResponseBYE
)

// ResponseStatusMapping is the text representation of a ResponseStatus
var ResponseStatusMapping = map[ResponseStatus]string{
	ResponseOK:      "OK",
	ResponseNO:      "NO",
	ResponseBAD:     "BAD",
	ResponsePREAUTH: "PREAUTH",
	ResponseBYE:     "BYE",
}

const (
	// ALERT represents the ALERT response code
	ALERT = ResponseCode("ALERT")
	// BADCHARSET represents the BADCHARSET response code
	BADCHARSET = ResponseCode("BADCHARSET")
	// CAPABILITY represents the CAPABILITY response code
	CAPABILITY = ResponseCode("CAPABILITY")
	// PARSE represents the PARSE response code
	PARSE = ResponseCode("PARSE")
	// PERMANENTFLAGS represents the PERMANENTFLAGS response code
	PERMANENTFLAGS = ResponseCode("PERMANENTFLAGS")
	// READONLY represents the READ-ONLY response code
	READONLY = ResponseCode("READ-ONLY")
	// READWRITE represents the READ-WRITE response code
	READWRITE = ResponseCode("READ-WRITE")
	// TRYCREATE represents the TRYCREATE response code
	TRYCREATE = ResponseCode("TRYCREATE")
	// UIDNEXT represents the UIDNEXT response code
	UIDNEXT = ResponseCode("UIDNEXT")
	// UIDVALIDITY represents the UIDVALIDITY response code
	UIDVALIDITY = ResponseCode("UIDVALIDITY")
	// UNSEEN represents the UNSEEN response code
	UNSEEN = ResponseCode("UNSEEN")
)

// Code returns a pointer to a ResponseCode value
func Code(r ResponseCode) *ResponseCode {
	return &r
}

// Status returns a pointer to a ResponseStatus value
func Status(r ResponseStatus) *ResponseStatus {
	return &r
}

// Lines returns the formatted SMTP reply
func (r Response) Lines() []string {
	l := r.Tag
	if r.Status != nil {
		l += " " + ResponseStatusMapping[*r.Status]
	}
	if c := r.Code; c != nil && len(*c) > 0 {
		l += " " + string(*c)
	}
	if len(r.Text) > 0 {
		l += " " + r.Text
	}
	l += "\r\n"
	return []string{l}
}

// ResponseIdent returns an OK server ready response
func ResponseIdent(revision, hostname, ident string) *Response {
	return &Response{"*", Status(ResponseOK), nil, revision + " " + ident + " (" + hostname + ") server ready", nil}
}

// ResponseLineTooLong returns a BAD error response
func ResponseLineTooLong(tag string) *Response {
	return &Response{tag, Status(ResponseBAD), nil, "line exceeded maximum length", nil}
}

// ResponseUnrecognisedCommand returns a tagged unrecognised command response
func ResponseUnrecognisedCommand(tag string) *Response {
	return &Response{tag, Status(ResponseBAD), nil, "unrecognised command", nil}
}

// ResponseSyntaxError returns a tagged syntax error response
func ResponseSyntaxError(tag string) *Response {
	return &Response{tag, Status(ResponseBAD), nil, "syntax error", nil}
}

// ResponseReadyToStartTLS returns a tagged OK response
func ResponseReadyToStartTLS(tag string, done func()) *Response {
	return &Response{tag, Status(ResponseOK), nil, "ready to start TLS", done}
}

// ResponseBye returns an untagged BYE response
func ResponseBye() *Response {
	return &Response{"*", Status(ResponseBYE), nil, "", nil}
}

// ResponseError returns a BAD response containing the error text
func ResponseError(tag string, err error) *Response {
	return &Response{tag, Status(ResponseBAD), nil, err.Error(), nil}
}

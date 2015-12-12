package imap

// State represents the state of an IMAP conversation
type State int

// IMAP message conversation states
const (
	INVALID = State(-1)
	PREAUTH = State(iota)
	AUTH
	SELECTED
	LOGOUT
)

// StateMap provides string representations of IMAP conversation states
var StateMap = map[State]string{
	INVALID:  "INVALID",
	PREAUTH:  "PREAUTH",
	AUTH:     "AUTH",
	SELECTED: "SELECTED",
	LOGOUT:   "LOGOUT",
}

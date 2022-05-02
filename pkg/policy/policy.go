// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"io"
	stdlog "log"
	"strconv"
	"strings"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
)

type Tracing int

const (
	TRACE_DISABLED Tracing = iota
	TRACE_ENABLED
	TRACE_VERBOSE
)

// TraceEnabled returns true if the SearchContext requests tracing.
func (s *SearchContext) TraceEnabled() bool {
	return s.Trace != TRACE_DISABLED
}

// PolicyTrace logs the given message into the SearchContext logger only if
// TRACE_ENABLED or TRACE_VERBOSE is enabled in the receiver's SearchContext.
func (s *SearchContext) PolicyTrace(format string, a ...interface{}) {
	if s.TraceEnabled() {
		log.Debugf(format, a...)
		if s.Logging != nil {
			format = "%-" + s.CallDepth() + "s" + format
			a = append([]interface{}{""}, a...)
			s.Logging.Printf(format, a...)
		}
	}
}

// PolicyTraceVerbose logs the given message into the SearchContext logger only
// if TRACE_VERBOSE is enabled in the receiver's SearchContext.
func (s *SearchContext) PolicyTraceVerbose(format string, a ...interface{}) {
	switch s.Trace {
	case TRACE_VERBOSE:
		log.Debugf(format, a...)
		if s.Logging != nil {
			s.Logging.Printf(format, a...)
		}
	}
}

// SearchContext defines the context while evaluating policy
type SearchContext struct {
	Trace   Tracing
	Depth   int
	Logging *stdlog.Logger
	From    labels.LabelArray
	To      labels.LabelArray
	DPorts  []*models.Port
	// rulesSelect specifies whether or not to check whether a rule which is
	// being analyzed using this SearchContext matches either From or To.
	// This is used to avoid using EndpointSelector.Matches() if possible,
	// since it is costly in terms of performance.
	rulesSelect bool
}

func (s *SearchContext) String() string {
	from := []string{}
	to := []string{}
	dports := []string{}
	for _, fromLabel := range s.From {
		from = append(from, fromLabel.String())
	}
	for _, toLabel := range s.To {
		to = append(to, toLabel.String())
	}
	for _, dport := range s.DPorts {
		if dport.Name != "" {
			var str strings.Builder
			str.Grow(len(dport.Name) + len(dport.Protocol) + 1)
			str.WriteString(dport.Name)
			str.WriteRune('/')
			str.WriteString(dport.Protocol)
			dports = append(dports, str.String())
		} else {
			var str strings.Builder
			dport_Str := strconv.FormatUint(uint64(dport.Port), 10)
			str.Grow(len(dport_Str) + len(dport.Protocol) + 1)
			str.WriteString(dport_Str)
			str.WriteRune('/')
			str.WriteString(dport.Protocol)
			dports = append(dports, str.String())
		}
	}
	from_str := strings.Join(from, ", ")
	to_str := strings.Join(to, ", ")
	dport_str := strings.Join(dports, ", ")
	var ret_str strings.Builder
	// the length of 'From: [] => To: [] Ports: []' is 28
	ret_str.Grow(len(from_str) + len(to_str) + len(dport_str) + 28)
	ret_str.WriteString("From: [")
	ret_str.WriteString(from_str)
	ret_str.WriteRune(']')
	ret_str.WriteString("=> To: [")
	ret_str.WriteString(to_str)
	ret_str.WriteRune(']')
	if len(dports) != 0 {
		ret_str.WriteString(" Ports: [")
		ret_str.WriteString(dport_str)
		ret_str.WriteRune(']')
	}
	return ret_str.String()
}

func (s *SearchContext) CallDepth() string {
	return strconv.Itoa(s.Depth * 2)
}

// WithLogger returns a shallow copy of the received SearchContext with the
// logging set to write to 'log'.
func (s *SearchContext) WithLogger(log io.Writer) *SearchContext {
	result := *s
	result.Logging = stdlog.New(log, "", 0)
	if result.Trace == TRACE_DISABLED {
		result.Trace = TRACE_ENABLED
	}
	return &result
}

// Translator is an interface for altering policy rules
type Translator interface {
	Translate(*api.Rule, *TranslationResult) error
}

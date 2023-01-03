// Copyright 2021 - 2023 PurpleSec Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package escape

import (
	"strings"
	"sync"
	"unicode/utf8"

	// Needed to include json vars
	_ "encoding/json"
	// Needed to use "go:linkname"
	_ "unsafe"
)

const hex = "0123456789abcdef"

var buf = sync.Pool{
	New: func() interface{} {
		return new(strings.Builder)
	},
}

//go:linkname htmlSafeSet encoding/json.safeSet
var htmlSafeSet [utf8.RuneSelf]bool

// JSON will escape the string provided into a JSON-like format, respecting all escaping. This will return
// the string value already in quotes. Acts like (and copied from) 'json.Marshal' on a string value.
func JSON(s string) string {
	if len(s) == 0 {
		return `""`
	}
	e := buf.Get().(*strings.Builder)
	e.Grow(2 + len(s))
	e.WriteByte('"')
	start := 0
	for i := 0; i < len(s); {
		if b := s[i]; b < utf8.RuneSelf {
			if htmlSafeSet[b] {
				i++
				continue
			}
			if start < i {
				e.WriteString(s[start:i])
			}
			e.WriteByte('\\')
			switch b {
			case '\\', '"':
				e.WriteByte(b)
			case '\n':
				e.WriteByte('n')
			case '\r':
				e.WriteByte('r')
			case '\t':
				e.WriteByte('t')
			default:
				e.WriteString(`u00`)
				e.WriteByte(hex[b>>4])
				e.WriteByte(hex[b&0xF])
			}
			i++
			start = i
			continue
		}
		c, size := utf8.DecodeRuneInString(s[i:])
		if c == utf8.RuneError && size == 1 {
			if start < i {
				e.WriteString(s[start:i])
			}
			e.WriteString(`\ufffd`)
			i += size
			start = i
			continue
		}
		if c == '\u2028' || c == '\u2029' {
			if start < i {
				e.WriteString(s[start:i])
			}
			e.WriteString(`\u202`)
			e.WriteByte(hex[c&0xF])
			i += size
			start = i
			continue
		}
		i += size
	}
	if start < len(s) {
		e.WriteString(s[start:])
	}
	e.WriteByte('"')
	r := e.String()
	e.Reset()
	buf.Put(e)
	return r
}

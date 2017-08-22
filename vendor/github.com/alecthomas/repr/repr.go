// Package repr attempts to represent Go values in a form that can be copy-and-pasted into source
// code directly.
//
// Some values (such as pointers to basic types) can not be represented directly in
// Go. These values will be output as `&<value>`. eg. `&23`
package repr

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"reflect"
)

// "Real" names of basic kinds, used to differentiate type aliases.
var realKindName = map[reflect.Kind]string{
	reflect.Bool:       "bool",
	reflect.Int:        "int",
	reflect.Int8:       "int8",
	reflect.Int16:      "int16",
	reflect.Int32:      "int32",
	reflect.Int64:      "int64",
	reflect.Uint:       "uint",
	reflect.Uint8:      "uint8",
	reflect.Uint16:     "uint16",
	reflect.Uint32:     "uint32",
	reflect.Uint64:     "uint64",
	reflect.Uintptr:    "uintptr",
	reflect.Float32:    "float32",
	reflect.Float64:    "float64",
	reflect.Complex64:  "complex64",
	reflect.Complex128: "complex128",
	reflect.Array:      "array",
	reflect.Chan:       "chan",
	reflect.Func:       "func",
	reflect.Map:        "map",
	reflect.Slice:      "slice",
	reflect.String:     "string",
}

// Default prints to os.Stdout with two space indentation.
var Default = New(os.Stdout, Indent("  "))

// An Option modifies the default behaviour of a Printer.
type Option func(o *Printer)

// Indent output by this much.
func Indent(indent string) Option { return func(o *Printer) { o.indent = indent } }

// NoIndent disables indenting.
func NoIndent() Option { return Indent("") }

// OmitEmpty omits empty field members from output.
func OmitEmpty() Option { return func(o *Printer) { o.omitEmpty = true } }

// Printer represents structs in a printable manner.
type Printer struct {
	indent    string
	omitEmpty bool
	w         io.Writer
}

// New creates a new Printer on w with the given Options.
func New(w io.Writer, options ...Option) *Printer {
	p := &Printer{w: w}
	for _, option := range options {
		option(p)
	}
	return p
}

func (p *Printer) nextIndent(indent string) string {
	if p.indent != "" {
		return indent + p.indent
	}
	return ""
}

func (p *Printer) thisIndent(indent string) string {
	if p.indent != "" {
		return indent
	}
	return ""
}

// Print the values.
func (p *Printer) Print(vs ...interface{}) {
	for _, v := range vs {
		p.reprValue(reflect.ValueOf(v), "")
	}
}

// Println prints each value on a new line.
func (p *Printer) Println(vs ...interface{}) {
	for _, v := range vs {
		p.reprValue(reflect.ValueOf(v), "")
		fmt.Fprintln(p.w)
	}
}

func (p *Printer) reprValue(v reflect.Value, indent string) {
	in := p.thisIndent(indent)
	ni := p.nextIndent(indent)
	switch v.Kind() {
	case reflect.Slice, reflect.Array:
		if p.omitEmpty && v.Len() == 0 {
			return
		}
		fmt.Fprintf(p.w, "%s{", v.Type())
		if v.Len() == 0 {
			fmt.Fprint(p.w, "}")
		} else {
			if p.indent != "" {
				fmt.Fprintf(p.w, "\n")
			}
			for i := 0; i < v.Len(); i++ {
				e := v.Index(i)
				fmt.Fprintf(p.w, "%s", ni)
				p.reprValue(e, ni)
				if p.indent != "" {
					fmt.Fprintf(p.w, ",\n")
				} else if i < v.Len()-1 {
					fmt.Fprintf(p.w, ", ")
				}
			}
			fmt.Fprintf(p.w, "%s}", in)
		}
	case reflect.Chan:
		fmt.Fprintf(p.w, "make(")
		fmt.Fprintf(p.w, "%s", v.Type())
		fmt.Fprintf(p.w, ", %d)", v.Cap())
	case reflect.Map:
		fmt.Fprintf(p.w, "%s{", v.Type())
		if p.indent != "" && v.Len() != 0 {
			fmt.Fprintf(p.w, "\n")
		}
		for i, k := range v.MapKeys() {
			kv := v.MapIndex(k)
			fmt.Fprintf(p.w, "%s", ni)
			p.reprValue(k, ni)
			fmt.Fprintf(p.w, ": ")
			p.reprValue(kv, ni)
			if p.indent != "" {
				fmt.Fprintf(p.w, ",\n")
			} else if i < v.Len()-1 {
				fmt.Fprintf(p.w, ", ")
			}
		}
		fmt.Fprintf(p.w, "%s}", in)
	case reflect.Struct:
		fmt.Fprintf(p.w, "%s{", v.Type())
		if p.indent != "" && v.NumField() != 0 {
			fmt.Fprintf(p.w, "\n")
		}
		for i := 0; i < v.NumField(); i++ {
			t := v.Type().Field(i)
			f := v.Field(i)
			if p.omitEmpty && isZero(f) {
				continue
			}
			fmt.Fprintf(p.w, "%s%s: ", ni, t.Name)
			p.reprValue(f, ni)
			if p.indent != "" {
				fmt.Fprintf(p.w, ",\n")
			} else if i < v.NumField()-1 {
				fmt.Fprintf(p.w, ", ")
			}
		}
		fmt.Fprintf(p.w, "%s}", indent)
	case reflect.Ptr:
		if v.IsNil() {
			fmt.Fprintf(p.w, "nil")
			return
		}
		fmt.Fprintf(p.w, "&")
		p.reprValue(v.Elem(), indent)
	case reflect.String:
		t := v.Type()
		if t.Name() != "string" {
			fmt.Fprintf(p.w, "%s(%q)", t, v.String())
		} else {
			fmt.Fprintf(p.w, "%q", v.String())
		}
	case reflect.Interface:
		if v.IsNil() {
			fmt.Fprintf(p.w, "interface {}(nil)")
		} else {
			p.reprValue(v.Elem(), indent)
		}
	default:
		t := v.Type()
		if t.Name() != realKindName[t.Kind()] {
			fmt.Fprintf(p.w, "%s(%v)", t, v)
		} else {
			fmt.Fprintf(p.w, "%v", v)
		}
	}
}

// String returns a string representing v.
func String(v interface{}, options ...Option) string {
	w := bytes.NewBuffer(nil)
	p := New(w, options...)
	p.Print(v)
	return w.String()
}

// Print v to os.Stdout on one line.
func Println(v interface{}, options ...Option) {
	New(os.Stdout, options...).Println(v)
}

// Print writes a representation of v to w.
func Print(w io.Writer, v interface{}, options ...Option) {
	New(w, options...).Print(v)
}

func isZero(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Array, reflect.String:
		return v.Len() == 0
	case reflect.Bool:
		return !v.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return v.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return v.Float() == 0
	case reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return v.IsNil()
	}
	return false
}

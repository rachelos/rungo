// Copyright 2014 rungo Author. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package utils

import (
	"fmt"
	"math/big"
	"reflect"
	"strconv"
	"time"
)

// StrTo is the target string
type StrTo string

// Set string
func (f *StrTo) Set(v string) {
	if v != "" {
		*f = StrTo(v)
	} else {
		f.Clear()
	}
}

// Clear string
func (f *StrTo) Clear() {
	*f = StrTo(rune(0x1E))
}

// Exist check string exist
func (f StrTo) Exist() bool {
	return string(f) != string(rune(0x1E))
}

// Bool string to bool
func (f StrTo) Bool() (bool, error) {
	return strconv.ParseBool(f.String())
}

// Float32 string to float32
func (f StrTo) Float32() (float32, error) {
	v, err := strconv.ParseFloat(f.String(), 32)
	return float32(v), err
}

// Float64 string to float64
func (f StrTo) Float64() (float64, error) {
	return strconv.ParseFloat(f.String(), 64)
}

// Int string to int
func (f StrTo) Int() (int, error) {
	v, err := strconv.ParseInt(f.String(), 10, 32)
	return int(v), err
}

// Int8 string to int8
func (f StrTo) Int8() (int8, error) {
	v, err := strconv.ParseInt(f.String(), 10, 8)
	return int8(v), err
}

// Int16 string to int16
func (f StrTo) Int16() (int16, error) {
	v, err := strconv.ParseInt(f.String(), 10, 16)
	return int16(v), err
}

// Int32 string to int32
func (f StrTo) Int32() (int32, error) {
	v, err := strconv.ParseInt(f.String(), 10, 32)
	return int32(v), err
}

// Int64 string to int64
func (f StrTo) Int64() (int64, error) {
	v, err := strconv.ParseInt(f.String(), 10, 64)
	if err != nil {
		i := new(big.Int)
		ni, ok := i.SetString(f.String(), 10) // octal
		if !ok {
			return v, err
		}
		return ni.Int64(), nil
	}
	return v, err
}

// Uint string to uint
func (f StrTo) Uint() (uint, error) {
	v, err := strconv.ParseUint(f.String(), 10, 32)
	return uint(v), err
}

// Uint8 string to uint8
func (f StrTo) Uint8() (uint8, error) {
	v, err := strconv.ParseUint(f.String(), 10, 8)
	return uint8(v), err
}

// Uint16 string to uint16
func (f StrTo) Uint16() (uint16, error) {
	v, err := strconv.ParseUint(f.String(), 10, 16)
	return uint16(v), err
}

// Uint32 string to uint32
func (f StrTo) Uint32() (uint32, error) {
	v, err := strconv.ParseUint(f.String(), 10, 32)
	return uint32(v), err
}

// Uint64 string to uint64
func (f StrTo) Uint64() (uint64, error) {
	v, err := strconv.ParseUint(f.String(), 10, 64)
	if err != nil {
		i := new(big.Int)
		ni, ok := i.SetString(f.String(), 10)
		if !ok {
			return v, err
		}
		return ni.Uint64(), nil
	}
	return v, err
}

// String string to string
func (f StrTo) String() string {
	if f.Exist() {
		return string(f)
	}
	return ""
}

// ToStr interface to string
func ToStr(value interface{}, args ...int) (s string) {
	switch v := value.(type) {
	case bool:
		s = strconv.FormatBool(v)
	case float32:
		s = strconv.FormatFloat(float64(v), 'f', ArgInt(args).Get(0, -1), ArgInt(args).Get(1, 32))
	case float64:
		s = strconv.FormatFloat(v, 'f', ArgInt(args).Get(0, -1), ArgInt(args).Get(1, 64))
	case int:
		s = strconv.FormatInt(int64(v), ArgInt(args).Get(0, 10))
	case int8:
		s = strconv.FormatInt(int64(v), ArgInt(args).Get(0, 10))
	case int16:
		s = strconv.FormatInt(int64(v), ArgInt(args).Get(0, 10))
	case int32:
		s = strconv.FormatInt(int64(v), ArgInt(args).Get(0, 10))
	case int64:
		s = strconv.FormatInt(v, ArgInt(args).Get(0, 10))
	case uint:
		s = strconv.FormatUint(uint64(v), ArgInt(args).Get(0, 10))
	case uint8:
		s = strconv.FormatUint(uint64(v), ArgInt(args).Get(0, 10))
	case uint16:
		s = strconv.FormatUint(uint64(v), ArgInt(args).Get(0, 10))
	case uint32:
		s = strconv.FormatUint(uint64(v), ArgInt(args).Get(0, 10))
	case uint64:
		s = strconv.FormatUint(v, ArgInt(args).Get(0, 10))
	case string:
		s = v
	case []byte:
		s = string(v)
	default:
		s = fmt.Sprintf("%v", v)
	}
	return s
}

// ToInt64 interface to int64
func ToInt64(value interface{}) (d int64) {
	val := reflect.ValueOf(value)
	switch value.(type) {
	case int, int8, int16, int32, int64:
		d = val.Int()
	case uint, uint8, uint16, uint32, uint64:
		d = int64(val.Uint())
	default:
		panic(fmt.Errorf("ToInt64 need numeric not `%T`", value))
	}
	return
}

type ArgString []string

// Get get string by index from string slice
func (a ArgString) Get(i int, args ...string) (r string) {
	if i >= 0 && i < len(a) {
		r = a[i]
	} else if len(args) > 0 {
		r = args[0]
	}
	return
}

type ArgInt []int

// Get get int by index from int slice
func (a ArgInt) Get(i int, args ...int) (r int) {
	if i >= 0 && i < len(a) {
		r = a[i]
	}
	if len(args) > 0 {
		r = args[0]
	}
	return
}

// TimeParse parse time to string with location
func TimeParse(dateString, format string) (time.Time, error) {
	tp, err := time.ParseInLocation(format, dateString, DefaultTimeLoc)
	return tp, err
}

// IndirectType get pointer indirect type
func IndirectType(v reflect.Type) reflect.Type {
	switch v.Kind() {
	case reflect.Ptr:
		return IndirectType(v.Elem())
	default:
		return v
	}
}

const (
	FormatTime     = "15:04:05"
	FormatDate     = "2006-01-02"
	FormatDateTime = "2006-01-02 15:04:05"
)

var (
	DefaultTimeLoc = time.Local
)

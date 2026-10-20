package nachalo

// #include <nachalo.h>
import "C"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"runtime"
	"sync/atomic"
	"unsafe"
)

// This is needed, because as of go 1.24
// type RustBuffer C.RustBuffer cannot have methods,
// RustBuffer is treated as non-local type
type GoRustBuffer struct {
	inner C.RustBuffer
}

type RustBufferI interface {
	AsReader() *bytes.Reader
	Free()
	ToGoBytes() []byte
	Data() unsafe.Pointer
	Len() uint64
	Capacity() uint64
}

// C.RustBuffer fields exposed as an interface so they can be accessed in different Go packages.
// See https://github.com/golang/go/issues/13467
type ExternalCRustBuffer interface {
	Data() unsafe.Pointer
	Len() uint64
	Capacity() uint64
}

func RustBufferFromC(b C.RustBuffer) ExternalCRustBuffer {
	return GoRustBuffer{
		inner: b,
	}
}

func CFromRustBuffer(b ExternalCRustBuffer) C.RustBuffer {
	return C.RustBuffer{
		capacity: C.uint64_t(b.Capacity()),
		len:      C.uint64_t(b.Len()),
		data:     (*C.uchar)(b.Data()),
	}
}

func RustBufferFromExternal(b ExternalCRustBuffer) GoRustBuffer {
	return GoRustBuffer{
		inner: C.RustBuffer{
			capacity: C.uint64_t(b.Capacity()),
			len:      C.uint64_t(b.Len()),
			data:     (*C.uchar)(b.Data()),
		},
	}
}

func (cb GoRustBuffer) Capacity() uint64 {
	return uint64(cb.inner.capacity)
}

func (cb GoRustBuffer) Len() uint64 {
	return uint64(cb.inner.len)
}

func (cb GoRustBuffer) Data() unsafe.Pointer {
	return unsafe.Pointer(cb.inner.data)
}

func (cb GoRustBuffer) AsReader() *bytes.Reader {
	b := unsafe.Slice((*byte)(cb.inner.data), C.uint64_t(cb.inner.len))
	return bytes.NewReader(b)
}

func (cb GoRustBuffer) Free() {
	rustCall(func(status *C.RustCallStatus) bool {
		C.ffi_nachalo_uniffi_rustbuffer_free(cb.inner, status)
		return false
	})
}

func (cb GoRustBuffer) ToGoBytes() []byte {
	return C.GoBytes(unsafe.Pointer(cb.inner.data), C.int(cb.inner.len))
}

func stringToRustBuffer(str string) C.RustBuffer {
	return bytesToRustBuffer([]byte(str))
}

func bytesToRustBuffer(b []byte) C.RustBuffer {
	if len(b) == 0 {
		return C.RustBuffer{}
	}
	// We can pass the pointer along here, as it is pinned
	// for the duration of this call
	foreign := C.ForeignBytes{
		len:  C.int(len(b)),
		data: (*C.uchar)(unsafe.Pointer(&b[0])),
	}

	return rustCall(func(status *C.RustCallStatus) C.RustBuffer {
		return C.ffi_nachalo_uniffi_rustbuffer_from_bytes(foreign, status)
	})
}

type BufLifter[GoType any] interface {
	Lift(value RustBufferI) GoType
}

type BufLowerer[GoType any] interface {
	Lower(value GoType) C.RustBuffer
}

type BufReader[GoType any] interface {
	Read(reader io.Reader) GoType
}

type BufWriter[GoType any] interface {
	Write(writer io.Writer, value GoType)
}

func LowerIntoRustBuffer[GoType any](bufWriter BufWriter[GoType], value GoType) C.RustBuffer {
	// This might be not the most efficient way but it does not require knowing allocation size
	// beforehand
	var buffer bytes.Buffer
	bufWriter.Write(&buffer, value)

	bytes, err := io.ReadAll(&buffer)
	if err != nil {
		panic(fmt.Errorf("reading written data: %w", err))
	}
	return bytesToRustBuffer(bytes)
}

func LiftFromRustBuffer[GoType any](bufReader BufReader[GoType], rbuf RustBufferI) GoType {
	defer rbuf.Free()
	reader := rbuf.AsReader()
	item := bufReader.Read(reader)
	if reader.Len() > 0 {
		// TODO: Remove this
		leftover, _ := io.ReadAll(reader)
		panic(fmt.Errorf("Junk remaining in buffer after lifting: %s", string(leftover)))
	}
	return item
}

func rustCallWithError[E any, U any](converter BufReader[E], callback func(*C.RustCallStatus) U) (U, E) {
	var status C.RustCallStatus
	returnValue := callback(&status)
	err := checkCallStatus(converter, status)
	return returnValue, err
}

func checkCallStatus[E any](converter BufReader[E], status C.RustCallStatus) E {
	switch status.code {
	case 0:
		var zero E
		return zero
	case 1:
		return LiftFromRustBuffer(converter, GoRustBuffer{inner: status.errorBuf})
	case 2:
		// when the rust code sees a panic, it tries to construct a rustBuffer
		// with the message.  but if that code panics, then it just sends back
		// an empty buffer.
		if status.errorBuf.len > 0 {
			panic(fmt.Errorf("%s", FfiConverterStringINSTANCE.Lift(GoRustBuffer{inner: status.errorBuf})))
		} else {
			panic(fmt.Errorf("Rust panicked while handling Rust panic"))
		}
	default:
		panic(fmt.Errorf("unknown status code: %d", status.code))
	}
}

func checkCallStatusUnknown(status C.RustCallStatus) error {
	switch status.code {
	case 0:
		return nil
	case 1:
		panic(fmt.Errorf("function not returning an error returned an error"))
	case 2:
		// when the rust code sees a panic, it tries to construct a C.RustBuffer
		// with the message.  but if that code panics, then it just sends back
		// an empty buffer.
		if status.errorBuf.len > 0 {
			panic(fmt.Errorf("%s", FfiConverterStringINSTANCE.Lift(GoRustBuffer{
				inner: status.errorBuf,
			})))
		} else {
			panic(fmt.Errorf("Rust panicked while handling Rust panic"))
		}
	default:
		return fmt.Errorf("unknown status code: %d", status.code)
	}
}

func rustCall[U any](callback func(*C.RustCallStatus) U) U {
	returnValue, err := rustCallWithError[error](nil, callback)
	if err != nil {
		panic(err)
	}
	return returnValue
}

type NativeError interface {
	AsError() error
}

func writeInt8(writer io.Writer, value int8) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeUint8(writer io.Writer, value uint8) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeInt16(writer io.Writer, value int16) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeUint16(writer io.Writer, value uint16) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeInt32(writer io.Writer, value int32) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeUint32(writer io.Writer, value uint32) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeInt64(writer io.Writer, value int64) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeUint64(writer io.Writer, value uint64) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeFloat32(writer io.Writer, value float32) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeFloat64(writer io.Writer, value float64) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func readInt8(reader io.Reader) int8 {
	var result int8
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readUint8(reader io.Reader) uint8 {
	var result uint8
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readInt16(reader io.Reader) int16 {
	var result int16
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readUint16(reader io.Reader) uint16 {
	var result uint16
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readInt32(reader io.Reader) int32 {
	var result int32
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readUint32(reader io.Reader) uint32 {
	var result uint32
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readInt64(reader io.Reader) int64 {
	var result int64
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readUint64(reader io.Reader) uint64 {
	var result uint64
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readFloat32(reader io.Reader) float32 {
	var result float32
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readFloat64(reader io.Reader) float64 {
	var result float64
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func init() {

	uniffiCheckChecksums()
}

func uniffiCheckChecksums() {
	// Get the bindings contract version from our ComponentInterface
	bindingsContractVersion := 30
	// Get the scaffolding contract version by calling the into the dylib
	scaffoldingContractVersion := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint32_t {
		return C.ffi_nachalo_uniffi_uniffi_contract_version()
	})
	if bindingsContractVersion != int(scaffoldingContractVersion) {
		// If this happens try cleaning and rebuilding your project
		panic("nachalo: UniFFI contract version mismatch")
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_nachalo_uniffi_checksum_func_appointment_words_a()
		})
		if checksum != 63416 {
			// If this happens try cleaning and rebuilding your project
			panic("nachalo: uniffi_nachalo_uniffi_checksum_func_appointment_words_a: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_nachalo_uniffi_checksum_func_appointment_words_b()
		})
		if checksum != 33015 {
			// If this happens try cleaning and rebuilding your project
			panic("nachalo: uniffi_nachalo_uniffi_checksum_func_appointment_words_b: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_nachalo_uniffi_checksum_func_msg1_len()
		})
		if checksum != 30379 {
			// If this happens try cleaning and rebuilding your project
			panic("nachalo: uniffi_nachalo_uniffi_checksum_func_msg1_len: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_nachalo_uniffi_checksum_func_msg2_len()
		})
		if checksum != 51472 {
			// If this happens try cleaning and rebuilding your project
			panic("nachalo: uniffi_nachalo_uniffi_checksum_func_msg2_len: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_nachalo_uniffi_checksum_func_msg3_len()
		})
		if checksum != 8646 {
			// If this happens try cleaning and rebuilding your project
			panic("nachalo: uniffi_nachalo_uniffi_checksum_func_msg3_len: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_nachalo_uniffi_checksum_func_new_physical_token()
		})
		if checksum != 28242 {
			// If this happens try cleaning and rebuilding your project
			panic("nachalo: uniffi_nachalo_uniffi_checksum_func_new_physical_token: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_nachalo_uniffi_checksum_func_payload_ceiling()
		})
		if checksum != 12292 {
			// If this happens try cleaning and rebuilding your project
			panic("nachalo: uniffi_nachalo_uniffi_checksum_func_payload_ceiling: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_nachalo_uniffi_checksum_func_rendezvous_len()
		})
		if checksum != 41950 {
			// If this happens try cleaning and rebuilding your project
			panic("nachalo: uniffi_nachalo_uniffi_checksum_func_rendezvous_len: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_nachalo_uniffi_checksum_func_token_len()
		})
		if checksum != 65301 {
			// If this happens try cleaning and rebuilding your project
			panic("nachalo: uniffi_nachalo_uniffi_checksum_func_token_len: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_nachalo_uniffi_checksum_func_word_count()
		})
		if checksum != 47719 {
			// If this happens try cleaning and rebuilding your project
			panic("nachalo: uniffi_nachalo_uniffi_checksum_func_word_count: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_nachalo_uniffi_checksum_func_words()
		})
		if checksum != 49819 {
			// If this happens try cleaning and rebuilding your project
			panic("nachalo: uniffi_nachalo_uniffi_checksum_func_words: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_nachalo_uniffi_checksum_method_config_with_appointment_window()
		})
		if checksum != 58436 {
			// If this happens try cleaning and rebuilding your project
			panic("nachalo: uniffi_nachalo_uniffi_checksum_method_config_with_appointment_window: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_nachalo_uniffi_checksum_method_config_with_invite_ttl()
		})
		if checksum != 40676 {
			// If this happens try cleaning and rebuilding your project
			panic("nachalo: uniffi_nachalo_uniffi_checksum_method_config_with_invite_ttl: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_nachalo_uniffi_checksum_method_config_with_max_answers()
		})
		if checksum != 47985 {
			// If this happens try cleaning and rebuilding your project
			panic("nachalo: uniffi_nachalo_uniffi_checksum_method_config_with_max_answers: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_nachalo_uniffi_checksum_method_config_with_max_payload()
		})
		if checksum != 37983 {
			// If this happens try cleaning and rebuilding your project
			panic("nachalo: uniffi_nachalo_uniffi_checksum_method_config_with_max_payload: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_nachalo_uniffi_checksum_method_established_export()
		})
		if checksum != 18879 {
			// If this happens try cleaning and rebuilding your project
			panic("nachalo: uniffi_nachalo_uniffi_checksum_method_established_export: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_nachalo_uniffi_checksum_method_established_key()
		})
		if checksum != 54815 {
			// If this happens try cleaning and rebuilding your project
			panic("nachalo: uniffi_nachalo_uniffi_checksum_method_established_key: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_nachalo_uniffi_checksum_method_established_peer_payload()
		})
		if checksum != 2515 {
			// If this happens try cleaning and rebuilding your project
			panic("nachalo: uniffi_nachalo_uniffi_checksum_method_established_peer_payload: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_nachalo_uniffi_checksum_method_established_role()
		})
		if checksum != 10261 {
			// If this happens try cleaning and rebuilding your project
			panic("nachalo: uniffi_nachalo_uniffi_checksum_method_established_role: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_nachalo_uniffi_checksum_method_established_transcript()
		})
		if checksum != 16131 {
			// If this happens try cleaning and rebuilding your project
			panic("nachalo: uniffi_nachalo_uniffi_checksum_method_established_transcript: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_nachalo_uniffi_checksum_method_initiator_deadline()
		})
		if checksum != 46751 {
			// If this happens try cleaning and rebuilding your project
			panic("nachalo: uniffi_nachalo_uniffi_checksum_method_initiator_deadline: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_nachalo_uniffi_checksum_method_initiator_finish()
		})
		if checksum != 2991 {
			// If this happens try cleaning and rebuilding your project
			panic("nachalo: uniffi_nachalo_uniffi_checksum_method_initiator_finish: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_nachalo_uniffi_checksum_method_initiator_msg1()
		})
		if checksum != 51934 {
			// If this happens try cleaning and rebuilding your project
			panic("nachalo: uniffi_nachalo_uniffi_checksum_method_initiator_msg1: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_nachalo_uniffi_checksum_method_invitation_rendezvous()
		})
		if checksum != 18395 {
			// If this happens try cleaning and rebuilding your project
			panic("nachalo: uniffi_nachalo_uniffi_checksum_method_invitation_rendezvous: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_nachalo_uniffi_checksum_method_listener_respond()
		})
		if checksum != 15947 {
			// If this happens try cleaning and rebuilding your project
			panic("nachalo: uniffi_nachalo_uniffi_checksum_method_listener_respond: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_nachalo_uniffi_checksum_method_responder_deadline()
		})
		if checksum != 9468 {
			// If this happens try cleaning and rebuilding your project
			panic("nachalo: uniffi_nachalo_uniffi_checksum_method_responder_deadline: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_nachalo_uniffi_checksum_method_responder_finish()
		})
		if checksum != 64900 {
			// If this happens try cleaning and rebuilding your project
			panic("nachalo: uniffi_nachalo_uniffi_checksum_method_responder_finish: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_nachalo_uniffi_checksum_method_unconfirmed_confirm()
		})
		if checksum != 7446 {
			// If this happens try cleaning and rebuilding your project
			panic("nachalo: uniffi_nachalo_uniffi_checksum_method_unconfirmed_confirm: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_nachalo_uniffi_checksum_method_unconfirmed_role()
		})
		if checksum != 4055 {
			// If this happens try cleaning and rebuilding your project
			panic("nachalo: uniffi_nachalo_uniffi_checksum_method_unconfirmed_role: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_nachalo_uniffi_checksum_method_unconfirmed_safety_words()
		})
		if checksum != 39685 {
			// If this happens try cleaning and rebuilding your project
			panic("nachalo: uniffi_nachalo_uniffi_checksum_method_unconfirmed_safety_words: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_nachalo_uniffi_checksum_method_unconfirmed_verify()
		})
		if checksum != 36233 {
			// If this happens try cleaning and rebuilding your project
			panic("nachalo: uniffi_nachalo_uniffi_checksum_method_unconfirmed_verify: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_nachalo_uniffi_checksum_constructor_config_new()
		})
		if checksum != 32199 {
			// If this happens try cleaning and rebuilding your project
			panic("nachalo: uniffi_nachalo_uniffi_checksum_constructor_config_new: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_nachalo_uniffi_checksum_constructor_initiator_start()
		})
		if checksum != 13451 {
			// If this happens try cleaning and rebuilding your project
			panic("nachalo: uniffi_nachalo_uniffi_checksum_constructor_initiator_start: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_nachalo_uniffi_checksum_constructor_invitation_appointment()
		})
		if checksum != 29237 {
			// If this happens try cleaning and rebuilding your project
			panic("nachalo: uniffi_nachalo_uniffi_checksum_constructor_invitation_appointment: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_nachalo_uniffi_checksum_constructor_invitation_live()
		})
		if checksum != 30565 {
			// If this happens try cleaning and rebuilding your project
			panic("nachalo: uniffi_nachalo_uniffi_checksum_constructor_invitation_live: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_nachalo_uniffi_checksum_constructor_invitation_physical_token()
		})
		if checksum != 52934 {
			// If this happens try cleaning and rebuilding your project
			panic("nachalo: uniffi_nachalo_uniffi_checksum_constructor_invitation_physical_token: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_nachalo_uniffi_checksum_constructor_listener_new()
		})
		if checksum != 33711 {
			// If this happens try cleaning and rebuilding your project
			panic("nachalo: uniffi_nachalo_uniffi_checksum_constructor_listener_new: UniFFI API checksum mismatch")
		}
	}
}

type FfiConverterUint16 struct{}

var FfiConverterUint16INSTANCE = FfiConverterUint16{}

func (FfiConverterUint16) Lower(value uint16) C.uint16_t {
	return C.uint16_t(value)
}

func (FfiConverterUint16) Write(writer io.Writer, value uint16) {
	writeUint16(writer, value)
}

func (FfiConverterUint16) Lift(value C.uint16_t) uint16 {
	return uint16(value)
}

func (FfiConverterUint16) Read(reader io.Reader) uint16 {
	return readUint16(reader)
}

type FfiDestroyerUint16 struct{}

func (FfiDestroyerUint16) Destroy(_ uint16) {}

type FfiConverterUint32 struct{}

var FfiConverterUint32INSTANCE = FfiConverterUint32{}

func (FfiConverterUint32) Lower(value uint32) C.uint32_t {
	return C.uint32_t(value)
}

func (FfiConverterUint32) Write(writer io.Writer, value uint32) {
	writeUint32(writer, value)
}

func (FfiConverterUint32) Lift(value C.uint32_t) uint32 {
	return uint32(value)
}

func (FfiConverterUint32) Read(reader io.Reader) uint32 {
	return readUint32(reader)
}

type FfiDestroyerUint32 struct{}

func (FfiDestroyerUint32) Destroy(_ uint32) {}

type FfiConverterUint64 struct{}

var FfiConverterUint64INSTANCE = FfiConverterUint64{}

func (FfiConverterUint64) Lower(value uint64) C.uint64_t {
	return C.uint64_t(value)
}

func (FfiConverterUint64) Write(writer io.Writer, value uint64) {
	writeUint64(writer, value)
}

func (FfiConverterUint64) Lift(value C.uint64_t) uint64 {
	return uint64(value)
}

func (FfiConverterUint64) Read(reader io.Reader) uint64 {
	return readUint64(reader)
}

type FfiDestroyerUint64 struct{}

func (FfiDestroyerUint64) Destroy(_ uint64) {}

type FfiConverterString struct{}

var FfiConverterStringINSTANCE = FfiConverterString{}

func (FfiConverterString) Lift(rb RustBufferI) string {
	defer rb.Free()
	reader := rb.AsReader()
	b, err := io.ReadAll(reader)
	if err != nil {
		panic(fmt.Errorf("reading reader: %w", err))
	}
	return string(b)
}

func (FfiConverterString) Read(reader io.Reader) string {
	length := readInt32(reader)
	buffer := make([]byte, length)
	read_length, err := reader.Read(buffer)
	if err != nil && err != io.EOF {
		panic(err)
	}
	if read_length != int(length) {
		panic(fmt.Errorf("bad read length when reading string, expected %d, read %d", length, read_length))
	}
	return string(buffer)
}

func (FfiConverterString) Lower(value string) C.RustBuffer {
	return stringToRustBuffer(value)
}

func (c FfiConverterString) LowerExternal(value string) ExternalCRustBuffer {
	return RustBufferFromC(stringToRustBuffer(value))
}

func (FfiConverterString) Write(writer io.Writer, value string) {
	if len(value) > math.MaxInt32 {
		panic("String is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	write_length, err := io.WriteString(writer, value)
	if err != nil {
		panic(err)
	}
	if write_length != len(value) {
		panic(fmt.Errorf("bad write length when writing string, expected %d, written %d", len(value), write_length))
	}
}

type FfiDestroyerString struct{}

func (FfiDestroyerString) Destroy(_ string) {}

type FfiConverterBytes struct{}

var FfiConverterBytesINSTANCE = FfiConverterBytes{}

func (c FfiConverterBytes) Lower(value []byte) C.RustBuffer {
	return LowerIntoRustBuffer[[]byte](c, value)
}

func (c FfiConverterBytes) LowerExternal(value []byte) ExternalCRustBuffer {
	return RustBufferFromC(c.Lower(value))
}

func (c FfiConverterBytes) Write(writer io.Writer, value []byte) {
	if len(value) > math.MaxInt32 {
		panic("[]byte is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	write_length, err := writer.Write(value)
	if err != nil {
		panic(err)
	}
	if write_length != len(value) {
		panic(fmt.Errorf("bad write length when writing []byte, expected %d, written %d", len(value), write_length))
	}
}

func (c FfiConverterBytes) Lift(rb RustBufferI) []byte {
	return LiftFromRustBuffer[[]byte](c, rb)
}

func (c FfiConverterBytes) Read(reader io.Reader) []byte {
	length := readInt32(reader)
	buffer := make([]byte, length)
	read_length, err := reader.Read(buffer)
	if err != nil && err != io.EOF {
		panic(err)
	}
	if read_length != int(length) {
		panic(fmt.Errorf("bad read length when reading []byte, expected %d, read %d", length, read_length))
	}
	return buffer
}

type FfiDestroyerBytes struct{}

func (FfiDestroyerBytes) Destroy(_ []byte) {}

// Below is an implementation of synchronization requirements outlined in the link.
// https://github.com/mozilla/uniffi-rs/blob/0dc031132d9493ca812c3af6e7dd60ad2ea95bf0/uniffi_bindgen/src/bindings/kotlin/templates/ObjectRuntime.kt#L31

type FfiObject struct {
	handle        C.uint64_t
	callCounter   atomic.Int64
	cloneFunction func(C.uint64_t, *C.RustCallStatus) C.uint64_t
	freeFunction  func(C.uint64_t, *C.RustCallStatus)
	destroyed     atomic.Bool
}

func newFfiObject(
	handle C.uint64_t,
	cloneFunction func(C.uint64_t, *C.RustCallStatus) C.uint64_t,
	freeFunction func(C.uint64_t, *C.RustCallStatus),
) FfiObject {
	return FfiObject{
		handle:        handle,
		cloneFunction: cloneFunction,
		freeFunction:  freeFunction,
	}
}

func (ffiObject *FfiObject) incrementPointer(debugName string) C.uint64_t {
	for {
		counter := ffiObject.callCounter.Load()
		if counter <= -1 {
			panic(fmt.Errorf("%v object has already been destroyed", debugName))
		}
		if counter == math.MaxInt64 {
			panic(fmt.Errorf("%v object call counter would overflow", debugName))
		}
		if ffiObject.callCounter.CompareAndSwap(counter, counter+1) {
			break
		}
	}

	return rustCall(func(status *C.RustCallStatus) C.uint64_t {
		return ffiObject.cloneFunction(ffiObject.handle, status)
	})
}

func (ffiObject *FfiObject) decrementPointer() {
	if ffiObject.callCounter.Add(-1) == -1 {
		ffiObject.freeRustArcPtr()
	}
}

func (ffiObject *FfiObject) destroy() {
	if ffiObject.destroyed.CompareAndSwap(false, true) {
		if ffiObject.callCounter.Add(-1) == -1 {
			ffiObject.freeRustArcPtr()
		}
	}
}

func (ffiObject *FfiObject) freeRustArcPtr() {
	if ffiObject.handle == 0 {
		return
	}
	rustCall(func(status *C.RustCallStatus) int32 {
		ffiObject.freeFunction(ffiObject.handle, status)
		return 0
	})
}

// This device's limits: a profile and the values chosen within its ranges.
type ConfigInterface interface {
	// How long after its start time an appointment works, in seconds.
	WithAppointmentWindow(seconds uint64) (*Config, error)
	// How long each pending step lives, in seconds.
	WithInviteTtl(seconds uint64) (*Config, error)
	// Wrong msg2 taken as initiator, and msg1 answered as responder, per invitation.
	WithMaxAnswers(answers uint16) (*Config, error)
	// Largest payload this device sends, in bytes.
	WithMaxPayload(bytes uint32) (*Config, error)
}

// This device's limits: a profile and the values chosen within its ranges.
type Config struct {
	ffiObject FfiObject
}

// Every value at the profile's default.
func NewConfig(profile Profile) *Config {
	return FfiConverterConfigINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint64_t {
		return C.uniffi_nachalo_uniffi_fn_constructor_config_new(FfiConverterProfileINSTANCE.Lower(profile), _uniffiStatus)
	}))
}

// How long after its start time an appointment works, in seconds.
func (_self *Config) WithAppointmentWindow(seconds uint64) (*Config, error) {
	_pointer := _self.ffiObject.incrementPointer("*Config")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*NachaloError](FfiConverterNachaloError{}, func(_uniffiStatus *C.RustCallStatus) C.uint64_t {
		return C.uniffi_nachalo_uniffi_fn_method_config_with_appointment_window(
			_pointer, FfiConverterUint64INSTANCE.Lower(seconds), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue *Config
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterConfigINSTANCE.Lift(_uniffiRV), nil
	}
}

// How long each pending step lives, in seconds.
func (_self *Config) WithInviteTtl(seconds uint64) (*Config, error) {
	_pointer := _self.ffiObject.incrementPointer("*Config")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*NachaloError](FfiConverterNachaloError{}, func(_uniffiStatus *C.RustCallStatus) C.uint64_t {
		return C.uniffi_nachalo_uniffi_fn_method_config_with_invite_ttl(
			_pointer, FfiConverterUint64INSTANCE.Lower(seconds), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue *Config
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterConfigINSTANCE.Lift(_uniffiRV), nil
	}
}

// Wrong msg2 taken as initiator, and msg1 answered as responder, per invitation.
func (_self *Config) WithMaxAnswers(answers uint16) (*Config, error) {
	_pointer := _self.ffiObject.incrementPointer("*Config")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*NachaloError](FfiConverterNachaloError{}, func(_uniffiStatus *C.RustCallStatus) C.uint64_t {
		return C.uniffi_nachalo_uniffi_fn_method_config_with_max_answers(
			_pointer, FfiConverterUint16INSTANCE.Lower(answers), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue *Config
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterConfigINSTANCE.Lift(_uniffiRV), nil
	}
}

// Largest payload this device sends, in bytes.
func (_self *Config) WithMaxPayload(bytes uint32) (*Config, error) {
	_pointer := _self.ffiObject.incrementPointer("*Config")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*NachaloError](FfiConverterNachaloError{}, func(_uniffiStatus *C.RustCallStatus) C.uint64_t {
		return C.uniffi_nachalo_uniffi_fn_method_config_with_max_payload(
			_pointer, FfiConverterUint32INSTANCE.Lower(bytes), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue *Config
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterConfigINSTANCE.Lift(_uniffiRV), nil
	}
}
func (object *Config) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterConfig struct{}

var FfiConverterConfigINSTANCE = FfiConverterConfig{}

func (c FfiConverterConfig) Lift(handle C.uint64_t) *Config {
	result := &Config{
		newFfiObject(
			handle,
			func(handle C.uint64_t, status *C.RustCallStatus) C.uint64_t {
				return C.uniffi_nachalo_uniffi_fn_clone_config(handle, status)
			},
			func(handle C.uint64_t, status *C.RustCallStatus) {
				C.uniffi_nachalo_uniffi_fn_free_config(handle, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*Config).Destroy)
	return result
}

func (c FfiConverterConfig) Read(reader io.Reader) *Config {
	return c.Lift(C.uint64_t(readUint64(reader)))
}

func (c FfiConverterConfig) Lower(value *Config) C.uint64_t {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the handle will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked handle.
	handle := value.ffiObject.incrementPointer("*Config")
	defer value.ffiObject.decrementPointer()
	return handle
}

func (c FfiConverterConfig) Write(writer io.Writer, value *Config) {
	writeUint64(writer, uint64(c.Lower(value)))
}

func LiftFromExternalConfig(handle uint64) *Config {
	return FfiConverterConfigINSTANCE.Lift(C.uint64_t(handle))
}

func LowerToExternalConfig(value *Config) uint64 {
	return uint64(FfiConverterConfigINSTANCE.Lower(value))
}

type FfiDestroyerConfig struct{}

func (_ FfiDestroyerConfig) Destroy(value *Config) {
	value.Destroy()
}

// What both sides share once the safety words matched. Holds the key: release it once done.
type EstablishedInterface interface {
	// An independent 32-byte key for `label`, equal on both sides. Secret: the returned bytes
	// are not zeroized.
	Export(label []byte) []byte
	// The shared secret, 32 bytes, equal on both sides. Secret: the returned bytes are not
	// zeroized; prefer `export`.
	Key() []byte
	// The payload the other side sent. The returned bytes are not zeroized.
	PeerPayload() []byte
	// Which side this device played.
	Role() Role
	// Hash of the whole handshake, equal on both sides; public, good for channel binding.
	Transcript() []byte
}

// What both sides share once the safety words matched. Holds the key: release it once done.
type Established struct {
	ffiObject FfiObject
}

// An independent 32-byte key for `label`, equal on both sides. Secret: the returned bytes
// are not zeroized.
func (_self *Established) Export(label []byte) []byte {
	_pointer := _self.ffiObject.incrementPointer("*Established")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterBytesINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_nachalo_uniffi_fn_method_established_export(
				_pointer, FfiConverterBytesINSTANCE.Lower(label), _uniffiStatus),
		}
	}))
}

// The shared secret, 32 bytes, equal on both sides. Secret: the returned bytes are not
// zeroized; prefer `export`.
func (_self *Established) Key() []byte {
	_pointer := _self.ffiObject.incrementPointer("*Established")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterBytesINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_nachalo_uniffi_fn_method_established_key(
				_pointer, _uniffiStatus),
		}
	}))
}

// The payload the other side sent. The returned bytes are not zeroized.
func (_self *Established) PeerPayload() []byte {
	_pointer := _self.ffiObject.incrementPointer("*Established")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterBytesINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_nachalo_uniffi_fn_method_established_peer_payload(
				_pointer, _uniffiStatus),
		}
	}))
}

// Which side this device played.
func (_self *Established) Role() Role {
	_pointer := _self.ffiObject.incrementPointer("*Established")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterRoleINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_nachalo_uniffi_fn_method_established_role(
				_pointer, _uniffiStatus),
		}
	}))
}

// Hash of the whole handshake, equal on both sides; public, good for channel binding.
func (_self *Established) Transcript() []byte {
	_pointer := _self.ffiObject.incrementPointer("*Established")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterBytesINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_nachalo_uniffi_fn_method_established_transcript(
				_pointer, _uniffiStatus),
		}
	}))
}
func (object *Established) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterEstablished struct{}

var FfiConverterEstablishedINSTANCE = FfiConverterEstablished{}

func (c FfiConverterEstablished) Lift(handle C.uint64_t) *Established {
	result := &Established{
		newFfiObject(
			handle,
			func(handle C.uint64_t, status *C.RustCallStatus) C.uint64_t {
				return C.uniffi_nachalo_uniffi_fn_clone_established(handle, status)
			},
			func(handle C.uint64_t, status *C.RustCallStatus) {
				C.uniffi_nachalo_uniffi_fn_free_established(handle, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*Established).Destroy)
	return result
}

func (c FfiConverterEstablished) Read(reader io.Reader) *Established {
	return c.Lift(C.uint64_t(readUint64(reader)))
}

func (c FfiConverterEstablished) Lower(value *Established) C.uint64_t {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the handle will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked handle.
	handle := value.ffiObject.incrementPointer("*Established")
	defer value.ffiObject.decrementPointer()
	return handle
}

func (c FfiConverterEstablished) Write(writer io.Writer, value *Established) {
	writeUint64(writer, uint64(c.Lower(value)))
}

func LiftFromExternalEstablished(handle uint64) *Established {
	return FfiConverterEstablishedINSTANCE.Lift(C.uint64_t(handle))
}

func LowerToExternalEstablished(value *Established) uint64 {
	return uint64(FfiConverterEstablishedINSTANCE.Lower(value))
}

type FfiDestroyerEstablished struct{}

func (_ FfiDestroyerEstablished) Destroy(value *Established) {
	value.Destroy()
}

// A's pending handshake, from `start` until msg2 arrives. Holds secrets: release it once done.
type InitiatorInterface interface {
	// The last second on the monotonic clock this invitation may complete.
	Deadline() uint64
	// Completes the handshake with B's msg2: send msg3 to B. A wrong msg2 leaves this
	// initiator usable; once one succeeded, `Expired`.
	Finish(msg2 []byte, clock Clock) (Finished, error)
	// The first message, to send to the rendezvous.
	Msg1() []byte
}

// A's pending handshake, from `start` until msg2 arrives. Holds secrets: release it once done.
type Initiator struct {
	ffiObject FfiObject
}

// Starts the handshake: send `msg1()` to the invitation's rendezvous. `payload` is secret
// until the safety words match.
func InitiatorStart(invitation *Invitation, payload []byte, clock Clock) (*Initiator, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[*NachaloError](FfiConverterNachaloError{}, func(_uniffiStatus *C.RustCallStatus) C.uint64_t {
		return C.uniffi_nachalo_uniffi_fn_constructor_initiator_start(FfiConverterInvitationINSTANCE.Lower(invitation), FfiConverterBytesINSTANCE.Lower(payload), FfiConverterClockINSTANCE.Lower(clock), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue *Initiator
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterInitiatorINSTANCE.Lift(_uniffiRV), nil
	}
}

// The last second on the monotonic clock this invitation may complete.
func (_self *Initiator) Deadline() uint64 {
	_pointer := _self.ffiObject.incrementPointer("*Initiator")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterUint64INSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint64_t {
		return C.uniffi_nachalo_uniffi_fn_method_initiator_deadline(
			_pointer, _uniffiStatus)
	}))
}

// Completes the handshake with B's msg2: send msg3 to B. A wrong msg2 leaves this
// initiator usable; once one succeeded, `Expired`.
func (_self *Initiator) Finish(msg2 []byte, clock Clock) (Finished, error) {
	_pointer := _self.ffiObject.incrementPointer("*Initiator")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*NachaloError](FfiConverterNachaloError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_nachalo_uniffi_fn_method_initiator_finish(
				_pointer, FfiConverterBytesINSTANCE.Lower(msg2), FfiConverterClockINSTANCE.Lower(clock), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue Finished
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterFinishedINSTANCE.Lift(_uniffiRV), nil
	}
}

// The first message, to send to the rendezvous.
func (_self *Initiator) Msg1() []byte {
	_pointer := _self.ffiObject.incrementPointer("*Initiator")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterBytesINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_nachalo_uniffi_fn_method_initiator_msg1(
				_pointer, _uniffiStatus),
		}
	}))
}
func (object *Initiator) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterInitiator struct{}

var FfiConverterInitiatorINSTANCE = FfiConverterInitiator{}

func (c FfiConverterInitiator) Lift(handle C.uint64_t) *Initiator {
	result := &Initiator{
		newFfiObject(
			handle,
			func(handle C.uint64_t, status *C.RustCallStatus) C.uint64_t {
				return C.uniffi_nachalo_uniffi_fn_clone_initiator(handle, status)
			},
			func(handle C.uint64_t, status *C.RustCallStatus) {
				C.uniffi_nachalo_uniffi_fn_free_initiator(handle, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*Initiator).Destroy)
	return result
}

func (c FfiConverterInitiator) Read(reader io.Reader) *Initiator {
	return c.Lift(C.uint64_t(readUint64(reader)))
}

func (c FfiConverterInitiator) Lower(value *Initiator) C.uint64_t {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the handle will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked handle.
	handle := value.ffiObject.incrementPointer("*Initiator")
	defer value.ffiObject.decrementPointer()
	return handle
}

func (c FfiConverterInitiator) Write(writer io.Writer, value *Initiator) {
	writeUint64(writer, uint64(c.Lower(value)))
}

func LiftFromExternalInitiator(handle uint64) *Initiator {
	return FfiConverterInitiatorINSTANCE.Lift(C.uint64_t(handle))
}

func LowerToExternalInitiator(value *Initiator) uint64 {
	return uint64(FfiConverterInitiatorINSTANCE.Lower(value))
}

type FfiDestroyerInitiator struct{}

func (_ FfiDestroyerInitiator) Destroy(value *Initiator) {
	value.Destroy()
}

// What both sides derive from the shared secret of one invitation. Holds the secret: release it
// once both steps are done.
type InvitationInterface interface {
	// Public id where the side that starts leaves msg1 and the other looks for it.
	Rendezvous() []byte
}

// What both sides derive from the shared secret of one invitation. Holds the secret: release it
// once both steps are done.
type Invitation struct {
	ffiObject FfiObject
}

// First contact at the Unix time `at`, from A's and B's words.
func InvitationAppointment(wordsA string, wordsB string, at uint64, context []byte, nowUnix uint64, config *Config) (*Invitation, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[*NachaloError](FfiConverterNachaloError{}, func(_uniffiStatus *C.RustCallStatus) C.uint64_t {
		return C.uniffi_nachalo_uniffi_fn_constructor_invitation_appointment(FfiConverterStringINSTANCE.Lower(wordsA), FfiConverterStringINSTANCE.Lower(wordsB), FfiConverterUint64INSTANCE.Lower(at), FfiConverterBytesINSTANCE.Lower(context), FfiConverterUint64INSTANCE.Lower(nowUnix), FfiConverterConfigINSTANCE.Lower(config), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue *Invitation
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterInvitationINSTANCE.Lift(_uniffiRV), nil
	}
}

// Live first contact from `word_count()` words.
func InvitationLive(words string, context []byte, config *Config) (*Invitation, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[*NachaloError](FfiConverterNachaloError{}, func(_uniffiStatus *C.RustCallStatus) C.uint64_t {
		return C.uniffi_nachalo_uniffi_fn_constructor_invitation_live(FfiConverterStringINSTANCE.Lower(words), FfiConverterBytesINSTANCE.Lower(context), FfiConverterConfigINSTANCE.Lower(config), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue *Invitation
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterInvitationINSTANCE.Lift(_uniffiRV), nil
	}
}

// First contact through a physical token of `token_len()` bytes, `Rejected` otherwise.
func InvitationPhysicalToken(words string, token []byte, context []byte, nowUnix uint64, config *Config) (*Invitation, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[*NachaloError](FfiConverterNachaloError{}, func(_uniffiStatus *C.RustCallStatus) C.uint64_t {
		return C.uniffi_nachalo_uniffi_fn_constructor_invitation_physical_token(FfiConverterStringINSTANCE.Lower(words), FfiConverterBytesINSTANCE.Lower(token), FfiConverterBytesINSTANCE.Lower(context), FfiConverterUint64INSTANCE.Lower(nowUnix), FfiConverterConfigINSTANCE.Lower(config), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue *Invitation
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterInvitationINSTANCE.Lift(_uniffiRV), nil
	}
}

// Public id where the side that starts leaves msg1 and the other looks for it.
func (_self *Invitation) Rendezvous() []byte {
	_pointer := _self.ffiObject.incrementPointer("*Invitation")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterBytesINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_nachalo_uniffi_fn_method_invitation_rendezvous(
				_pointer, _uniffiStatus),
		}
	}))
}
func (object *Invitation) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterInvitation struct{}

var FfiConverterInvitationINSTANCE = FfiConverterInvitation{}

func (c FfiConverterInvitation) Lift(handle C.uint64_t) *Invitation {
	result := &Invitation{
		newFfiObject(
			handle,
			func(handle C.uint64_t, status *C.RustCallStatus) C.uint64_t {
				return C.uniffi_nachalo_uniffi_fn_clone_invitation(handle, status)
			},
			func(handle C.uint64_t, status *C.RustCallStatus) {
				C.uniffi_nachalo_uniffi_fn_free_invitation(handle, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*Invitation).Destroy)
	return result
}

func (c FfiConverterInvitation) Read(reader io.Reader) *Invitation {
	return c.Lift(C.uint64_t(readUint64(reader)))
}

func (c FfiConverterInvitation) Lower(value *Invitation) C.uint64_t {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the handle will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked handle.
	handle := value.ffiObject.incrementPointer("*Invitation")
	defer value.ffiObject.decrementPointer()
	return handle
}

func (c FfiConverterInvitation) Write(writer io.Writer, value *Invitation) {
	writeUint64(writer, uint64(c.Lower(value)))
}

func LiftFromExternalInvitation(handle uint64) *Invitation {
	return FfiConverterInvitationINSTANCE.Lift(C.uint64_t(handle))
}

func LowerToExternalInvitation(value *Invitation) uint64 {
	return uint64(FfiConverterInvitationINSTANCE.Lower(value))
}

type FfiDestroyerInvitation struct{}

func (_ FfiDestroyerInvitation) Destroy(value *Invitation) {
	value.Destroy()
}

// B's side of one invitation: answers each msg1 found at its rendezvous, up to the config's
// `max_answers`. Keep one per invitation. Holds the invitation's secret: release it once done.
type ListenerInterface interface {
	// Answers `msg1`: send msg2 back to A. `payload` is secret until the safety words match.
	Respond(msg1 []byte, payload []byte, clock Clock) (Answer, error)
}

// B's side of one invitation: answers each msg1 found at its rendezvous, up to the config's
// `max_answers`. Keep one per invitation. Holds the invitation's secret: release it once done.
type Listener struct {
	ffiObject FfiObject
}

// A listener with its own copy of `invitation`, which has answered nothing yet.
func NewListener(invitation *Invitation) *Listener {
	return FfiConverterListenerINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint64_t {
		return C.uniffi_nachalo_uniffi_fn_constructor_listener_new(FfiConverterInvitationINSTANCE.Lower(invitation), _uniffiStatus)
	}))
}

// Answers `msg1`: send msg2 back to A. `payload` is secret until the safety words match.
func (_self *Listener) Respond(msg1 []byte, payload []byte, clock Clock) (Answer, error) {
	_pointer := _self.ffiObject.incrementPointer("*Listener")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*NachaloError](FfiConverterNachaloError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_nachalo_uniffi_fn_method_listener_respond(
				_pointer, FfiConverterBytesINSTANCE.Lower(msg1), FfiConverterBytesINSTANCE.Lower(payload), FfiConverterClockINSTANCE.Lower(clock), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue Answer
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterAnswerINSTANCE.Lift(_uniffiRV), nil
	}
}
func (object *Listener) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterListener struct{}

var FfiConverterListenerINSTANCE = FfiConverterListener{}

func (c FfiConverterListener) Lift(handle C.uint64_t) *Listener {
	result := &Listener{
		newFfiObject(
			handle,
			func(handle C.uint64_t, status *C.RustCallStatus) C.uint64_t {
				return C.uniffi_nachalo_uniffi_fn_clone_listener(handle, status)
			},
			func(handle C.uint64_t, status *C.RustCallStatus) {
				C.uniffi_nachalo_uniffi_fn_free_listener(handle, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*Listener).Destroy)
	return result
}

func (c FfiConverterListener) Read(reader io.Reader) *Listener {
	return c.Lift(C.uint64_t(readUint64(reader)))
}

func (c FfiConverterListener) Lower(value *Listener) C.uint64_t {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the handle will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked handle.
	handle := value.ffiObject.incrementPointer("*Listener")
	defer value.ffiObject.decrementPointer()
	return handle
}

func (c FfiConverterListener) Write(writer io.Writer, value *Listener) {
	writeUint64(writer, uint64(c.Lower(value)))
}

func LiftFromExternalListener(handle uint64) *Listener {
	return FfiConverterListenerINSTANCE.Lift(C.uint64_t(handle))
}

func LowerToExternalListener(value *Listener) uint64 {
	return uint64(FfiConverterListenerINSTANCE.Lower(value))
}

type FfiDestroyerListener struct{}

func (_ FfiDestroyerListener) Destroy(value *Listener) {
	value.Destroy()
}

// B's answer to one msg1, until msg3 arrives. Holds secrets: release it once done.
type ResponderInterface interface {
	// The last second on the monotonic clock this answer may complete.
	Deadline() uint64
	// Completes the handshake with A's msg3. A forged msg3 leaves this answer usable.
	Finish(msg3 []byte, clock Clock) (*Unconfirmed, error)
}

// B's answer to one msg1, until msg3 arrives. Holds secrets: release it once done.
type Responder struct {
	ffiObject FfiObject
}

// The last second on the monotonic clock this answer may complete.
func (_self *Responder) Deadline() uint64 {
	_pointer := _self.ffiObject.incrementPointer("*Responder")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterUint64INSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint64_t {
		return C.uniffi_nachalo_uniffi_fn_method_responder_deadline(
			_pointer, _uniffiStatus)
	}))
}

// Completes the handshake with A's msg3. A forged msg3 leaves this answer usable.
func (_self *Responder) Finish(msg3 []byte, clock Clock) (*Unconfirmed, error) {
	_pointer := _self.ffiObject.incrementPointer("*Responder")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*NachaloError](FfiConverterNachaloError{}, func(_uniffiStatus *C.RustCallStatus) C.uint64_t {
		return C.uniffi_nachalo_uniffi_fn_method_responder_finish(
			_pointer, FfiConverterBytesINSTANCE.Lower(msg3), FfiConverterClockINSTANCE.Lower(clock), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue *Unconfirmed
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterUnconfirmedINSTANCE.Lift(_uniffiRV), nil
	}
}
func (object *Responder) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterResponder struct{}

var FfiConverterResponderINSTANCE = FfiConverterResponder{}

func (c FfiConverterResponder) Lift(handle C.uint64_t) *Responder {
	result := &Responder{
		newFfiObject(
			handle,
			func(handle C.uint64_t, status *C.RustCallStatus) C.uint64_t {
				return C.uniffi_nachalo_uniffi_fn_clone_responder(handle, status)
			},
			func(handle C.uint64_t, status *C.RustCallStatus) {
				C.uniffi_nachalo_uniffi_fn_free_responder(handle, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*Responder).Destroy)
	return result
}

func (c FfiConverterResponder) Read(reader io.Reader) *Responder {
	return c.Lift(C.uint64_t(readUint64(reader)))
}

func (c FfiConverterResponder) Lower(value *Responder) C.uint64_t {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the handle will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked handle.
	handle := value.ffiObject.incrementPointer("*Responder")
	defer value.ffiObject.decrementPointer()
	return handle
}

func (c FfiConverterResponder) Write(writer io.Writer, value *Responder) {
	writeUint64(writer, uint64(c.Lower(value)))
}

func LiftFromExternalResponder(handle uint64) *Responder {
	return FfiConverterResponderINSTANCE.Lift(C.uint64_t(handle))
}

func LowerToExternalResponder(value *Responder) uint64 {
	return uint64(FfiConverterResponderINSTANCE.Lower(value))
}

type FfiDestroyerResponder struct{}

func (_ FfiDestroyerResponder) Destroy(value *Responder) {
	value.Destroy()
}

// A finished handshake whose safety words nobody has compared yet. Holds the key: release it
// once done.
type UnconfirmedInterface interface {
	// B: opens the session once A says the safety words matched. Consumes this object, as in
	// Rust: any later call returns `Expired`.
	Confirm(clock Clock) (*Established, error)
	// Which side this device played.
	Role() Role
	// Four words, equal on both sides unless someone sits in the middle. B shows them, A types
	// them. `Expired` once confirmed.
	SafetyWords() (string, error)
	// A: opens the session once the user types the safety words B shows. A mismatch leaves it
	// pending until the deadline.
	Verify(typed string, clock Clock) (*Established, error)
}

// A finished handshake whose safety words nobody has compared yet. Holds the key: release it
// once done.
type Unconfirmed struct {
	ffiObject FfiObject
}

// B: opens the session once A says the safety words matched. Consumes this object, as in
// Rust: any later call returns `Expired`.
func (_self *Unconfirmed) Confirm(clock Clock) (*Established, error) {
	_pointer := _self.ffiObject.incrementPointer("*Unconfirmed")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*NachaloError](FfiConverterNachaloError{}, func(_uniffiStatus *C.RustCallStatus) C.uint64_t {
		return C.uniffi_nachalo_uniffi_fn_method_unconfirmed_confirm(
			_pointer, FfiConverterClockINSTANCE.Lower(clock), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue *Established
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterEstablishedINSTANCE.Lift(_uniffiRV), nil
	}
}

// Which side this device played.
func (_self *Unconfirmed) Role() Role {
	_pointer := _self.ffiObject.incrementPointer("*Unconfirmed")
	defer _self.ffiObject.decrementPointer()
	return FfiConverterRoleINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_nachalo_uniffi_fn_method_unconfirmed_role(
				_pointer, _uniffiStatus),
		}
	}))
}

// Four words, equal on both sides unless someone sits in the middle. B shows them, A types
// them. `Expired` once confirmed.
func (_self *Unconfirmed) SafetyWords() (string, error) {
	_pointer := _self.ffiObject.incrementPointer("*Unconfirmed")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*NachaloError](FfiConverterNachaloError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_nachalo_uniffi_fn_method_unconfirmed_safety_words(
				_pointer, _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue string
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterStringINSTANCE.Lift(_uniffiRV), nil
	}
}

// A: opens the session once the user types the safety words B shows. A mismatch leaves it
// pending until the deadline.
func (_self *Unconfirmed) Verify(typed string, clock Clock) (*Established, error) {
	_pointer := _self.ffiObject.incrementPointer("*Unconfirmed")
	defer _self.ffiObject.decrementPointer()
	_uniffiRV, _uniffiErr := rustCallWithError[*NachaloError](FfiConverterNachaloError{}, func(_uniffiStatus *C.RustCallStatus) C.uint64_t {
		return C.uniffi_nachalo_uniffi_fn_method_unconfirmed_verify(
			_pointer, FfiConverterStringINSTANCE.Lower(typed), FfiConverterClockINSTANCE.Lower(clock), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue *Established
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterEstablishedINSTANCE.Lift(_uniffiRV), nil
	}
}
func (object *Unconfirmed) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterUnconfirmed struct{}

var FfiConverterUnconfirmedINSTANCE = FfiConverterUnconfirmed{}

func (c FfiConverterUnconfirmed) Lift(handle C.uint64_t) *Unconfirmed {
	result := &Unconfirmed{
		newFfiObject(
			handle,
			func(handle C.uint64_t, status *C.RustCallStatus) C.uint64_t {
				return C.uniffi_nachalo_uniffi_fn_clone_unconfirmed(handle, status)
			},
			func(handle C.uint64_t, status *C.RustCallStatus) {
				C.uniffi_nachalo_uniffi_fn_free_unconfirmed(handle, status)
			},
		),
	}
	runtime.SetFinalizer(result, (*Unconfirmed).Destroy)
	return result
}

func (c FfiConverterUnconfirmed) Read(reader io.Reader) *Unconfirmed {
	return c.Lift(C.uint64_t(readUint64(reader)))
}

func (c FfiConverterUnconfirmed) Lower(value *Unconfirmed) C.uint64_t {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the handle will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked handle.
	handle := value.ffiObject.incrementPointer("*Unconfirmed")
	defer value.ffiObject.decrementPointer()
	return handle
}

func (c FfiConverterUnconfirmed) Write(writer io.Writer, value *Unconfirmed) {
	writeUint64(writer, uint64(c.Lower(value)))
}

func LiftFromExternalUnconfirmed(handle uint64) *Unconfirmed {
	return FfiConverterUnconfirmedINSTANCE.Lift(C.uint64_t(handle))
}

func LowerToExternalUnconfirmed(value *Unconfirmed) uint64 {
	return uint64(FfiConverterUnconfirmedINSTANCE.Lower(value))
}

type FfiDestroyerUnconfirmed struct{}

func (_ FfiDestroyerUnconfirmed) Destroy(value *Unconfirmed) {
	value.Destroy()
}

// What `Listener.respond` returns.
type Answer struct {
	// The pending answer, until msg3 arrives.
	Responder *Responder
	// The second message, to send back to A.
	Msg2 []byte
}

func (r *Answer) Destroy() {
	FfiDestroyerResponder{}.Destroy(r.Responder)
	FfiDestroyerBytes{}.Destroy(r.Msg2)
}

type FfiConverterAnswer struct{}

var FfiConverterAnswerINSTANCE = FfiConverterAnswer{}

func (c FfiConverterAnswer) Lift(rb RustBufferI) Answer {
	return LiftFromRustBuffer[Answer](c, rb)
}

func (c FfiConverterAnswer) Read(reader io.Reader) Answer {
	return Answer{
		FfiConverterResponderINSTANCE.Read(reader),
		FfiConverterBytesINSTANCE.Read(reader),
	}
}

func (c FfiConverterAnswer) Lower(value Answer) C.RustBuffer {
	return LowerIntoRustBuffer[Answer](c, value)
}

func (c FfiConverterAnswer) LowerExternal(value Answer) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[Answer](c, value))
}

func (c FfiConverterAnswer) Write(writer io.Writer, value Answer) {
	FfiConverterResponderINSTANCE.Write(writer, value.Responder)
	FfiConverterBytesINSTANCE.Write(writer, value.Msg2)
}

type FfiDestroyerAnswer struct{}

func (_ FfiDestroyerAnswer) Destroy(value Answer) {
	value.Destroy()
}

// The two clocks every step reads.
type Clock struct {
	// Monotonic seconds that keep counting while the device sleeps.
	Now uint64
	// Wall-clock Unix seconds.
	NowUnix uint64
}

func (r *Clock) Destroy() {
	FfiDestroyerUint64{}.Destroy(r.Now)
	FfiDestroyerUint64{}.Destroy(r.NowUnix)
}

type FfiConverterClock struct{}

var FfiConverterClockINSTANCE = FfiConverterClock{}

func (c FfiConverterClock) Lift(rb RustBufferI) Clock {
	return LiftFromRustBuffer[Clock](c, rb)
}

func (c FfiConverterClock) Read(reader io.Reader) Clock {
	return Clock{
		FfiConverterUint64INSTANCE.Read(reader),
		FfiConverterUint64INSTANCE.Read(reader),
	}
}

func (c FfiConverterClock) Lower(value Clock) C.RustBuffer {
	return LowerIntoRustBuffer[Clock](c, value)
}

func (c FfiConverterClock) LowerExternal(value Clock) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[Clock](c, value))
}

func (c FfiConverterClock) Write(writer io.Writer, value Clock) {
	FfiConverterUint64INSTANCE.Write(writer, value.Now)
	FfiConverterUint64INSTANCE.Write(writer, value.NowUnix)
}

type FfiDestroyerClock struct{}

func (_ FfiDestroyerClock) Destroy(value Clock) {
	value.Destroy()
}

// What `Initiator.finish` returns.
type Finished struct {
	// The handshake, until the safety words are compared.
	Unconfirmed *Unconfirmed
	// The third message, to send to B.
	Msg3 []byte
}

func (r *Finished) Destroy() {
	FfiDestroyerUnconfirmed{}.Destroy(r.Unconfirmed)
	FfiDestroyerBytes{}.Destroy(r.Msg3)
}

type FfiConverterFinished struct{}

var FfiConverterFinishedINSTANCE = FfiConverterFinished{}

func (c FfiConverterFinished) Lift(rb RustBufferI) Finished {
	return LiftFromRustBuffer[Finished](c, rb)
}

func (c FfiConverterFinished) Read(reader io.Reader) Finished {
	return Finished{
		FfiConverterUnconfirmedINSTANCE.Read(reader),
		FfiConverterBytesINSTANCE.Read(reader),
	}
}

func (c FfiConverterFinished) Lower(value Finished) C.RustBuffer {
	return LowerIntoRustBuffer[Finished](c, value)
}

func (c FfiConverterFinished) LowerExternal(value Finished) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[Finished](c, value))
}

func (c FfiConverterFinished) Write(writer io.Writer, value Finished) {
	FfiConverterUnconfirmedINSTANCE.Write(writer, value.Unconfirmed)
	FfiConverterBytesINSTANCE.Write(writer, value.Msg3)
}

type FfiDestroyerFinished struct{}

func (_ FfiDestroyerFinished) Destroy(value Finished) {
	value.Destroy()
}

// Why a step failed. On purpose, a rejected message does not say which check it failed.
type NachaloError struct {
	err error
}

// Convenience method to turn *NachaloError into error
// Avoiding treating nil pointer as non nil error interface
func (err *NachaloError) AsError() error {
	if err == nil {
		return nil
	} else {
		return err
	}
}

func (err NachaloError) Error() string {
	return fmt.Sprintf("NachaloError: %s", err.err.Error())
}

func (err NachaloError) Unwrap() error {
	return err.err
}

// Err* are used for checking error type with `errors.Is`
var ErrNachaloErrorBadWords = fmt.Errorf("NachaloErrorBadWords")
var ErrNachaloErrorExpired = fmt.Errorf("NachaloErrorExpired")
var ErrNachaloErrorPayloadTooLarge = fmt.Errorf("NachaloErrorPayloadTooLarge")
var ErrNachaloErrorRejected = fmt.Errorf("NachaloErrorRejected")
var ErrNachaloErrorOutOfRange = fmt.Errorf("NachaloErrorOutOfRange")
var ErrNachaloErrorRng = fmt.Errorf("NachaloErrorRng")
var ErrNachaloErrorOther = fmt.Errorf("NachaloErrorOther")

// Variant structs
// Not the expected number of words from the list.
type NachaloErrorBadWords struct {
}

// Not the expected number of words from the list.
func NewNachaloErrorBadWords() *NachaloError {
	return &NachaloError{err: &NachaloErrorBadWords{}}
}

func (e NachaloErrorBadWords) destroy() {
}

func (err NachaloErrorBadWords) Error() string {
	return fmt.Sprint("BadWords")
}

func (self NachaloErrorBadWords) Is(target error) bool {
	return target == ErrNachaloErrorBadWords
}

// Past its deadline, out of answers, already finished or confirmed, or outside the window
// of its appointment or physical token.
type NachaloErrorExpired struct {
}

// Past its deadline, out of answers, already finished or confirmed, or outside the window
// of its appointment or physical token.
func NewNachaloErrorExpired() *NachaloError {
	return &NachaloError{err: &NachaloErrorExpired{}}
}

func (e NachaloErrorExpired) destroy() {
}

func (err NachaloErrorExpired) Error() string {
	return fmt.Sprint("Expired")
}

func (self NachaloErrorExpired) Is(target error) bool {
	return target == ErrNachaloErrorExpired
}

// More than this device's `max_payload` bytes.
type NachaloErrorPayloadTooLarge struct {
}

// More than this device's `max_payload` bytes.
func NewNachaloErrorPayloadTooLarge() *NachaloError {
	return &NachaloError{err: &NachaloErrorPayloadTooLarge{}}
}

func (e NachaloErrorPayloadTooLarge) destroy() {
}

func (err NachaloErrorPayloadTooLarge) Error() string {
	return fmt.Sprint("PayloadTooLarge")
}

func (self NachaloErrorPayloadTooLarge) Is(target error) bool {
	return target == ErrNachaloErrorPayloadTooLarge
}

// Malformed input or failed confirmation, with no further detail.
type NachaloErrorRejected struct {
}

// Malformed input or failed confirmation, with no further detail.
func NewNachaloErrorRejected() *NachaloError {
	return &NachaloError{err: &NachaloErrorRejected{}}
}

func (e NachaloErrorRejected) destroy() {
}

func (err NachaloErrorRejected) Error() string {
	return fmt.Sprint("Rejected")
}

func (self NachaloErrorRejected) Is(target error) bool {
	return target == ErrNachaloErrorRejected
}

// A setting outside its profile's range, or a token expiry past the end of time.
type NachaloErrorOutOfRange struct {
}

// A setting outside its profile's range, or a token expiry past the end of time.
func NewNachaloErrorOutOfRange() *NachaloError {
	return &NachaloError{err: &NachaloErrorOutOfRange{}}
}

func (e NachaloErrorOutOfRange) destroy() {
}

func (err NachaloErrorOutOfRange) Error() string {
	return fmt.Sprint("OutOfRange")
}

func (self NachaloErrorOutOfRange) Is(target error) bool {
	return target == ErrNachaloErrorOutOfRange
}

// The OS random generator failed.
type NachaloErrorRng struct {
}

// The OS random generator failed.
func NewNachaloErrorRng() *NachaloError {
	return &NachaloError{err: &NachaloErrorRng{}}
}

func (e NachaloErrorRng) destroy() {
}

func (err NachaloErrorRng) Error() string {
	return fmt.Sprint("Rng")
}

func (self NachaloErrorRng) Is(target error) bool {
	return target == ErrNachaloErrorRng
}

// A failure this version of the bindings does not know.
type NachaloErrorOther struct {
}

// A failure this version of the bindings does not know.
func NewNachaloErrorOther() *NachaloError {
	return &NachaloError{err: &NachaloErrorOther{}}
}

func (e NachaloErrorOther) destroy() {
}

func (err NachaloErrorOther) Error() string {
	return fmt.Sprint("Other")
}

func (self NachaloErrorOther) Is(target error) bool {
	return target == ErrNachaloErrorOther
}

type FfiConverterNachaloError struct{}

var FfiConverterNachaloErrorINSTANCE = FfiConverterNachaloError{}

func (c FfiConverterNachaloError) Lift(eb RustBufferI) *NachaloError {
	return LiftFromRustBuffer[*NachaloError](c, eb)
}

func (c FfiConverterNachaloError) Lower(value *NachaloError) C.RustBuffer {
	return LowerIntoRustBuffer[*NachaloError](c, value)
}

func (c FfiConverterNachaloError) LowerExternal(value *NachaloError) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[*NachaloError](c, value))
}

func (c FfiConverterNachaloError) Read(reader io.Reader) *NachaloError {
	errorID := readUint32(reader)

	switch errorID {
	case 1:
		return &NachaloError{&NachaloErrorBadWords{}}
	case 2:
		return &NachaloError{&NachaloErrorExpired{}}
	case 3:
		return &NachaloError{&NachaloErrorPayloadTooLarge{}}
	case 4:
		return &NachaloError{&NachaloErrorRejected{}}
	case 5:
		return &NachaloError{&NachaloErrorOutOfRange{}}
	case 6:
		return &NachaloError{&NachaloErrorRng{}}
	case 7:
		return &NachaloError{&NachaloErrorOther{}}
	default:
		panic(fmt.Sprintf("Unknown error code %d in FfiConverterNachaloError.Read()", errorID))
	}
}

func (c FfiConverterNachaloError) Write(writer io.Writer, value *NachaloError) {
	switch variantValue := value.err.(type) {
	case *NachaloErrorBadWords:
		writeInt32(writer, 1)
	case *NachaloErrorExpired:
		writeInt32(writer, 2)
	case *NachaloErrorPayloadTooLarge:
		writeInt32(writer, 3)
	case *NachaloErrorRejected:
		writeInt32(writer, 4)
	case *NachaloErrorOutOfRange:
		writeInt32(writer, 5)
	case *NachaloErrorRng:
		writeInt32(writer, 6)
	case *NachaloErrorOther:
		writeInt32(writer, 7)
	default:
		_ = variantValue
		panic(fmt.Sprintf("invalid error value `%v` in FfiConverterNachaloError.Write", value))
	}
}

type FfiDestroyerNachaloError struct{}

func (_ FfiDestroyerNachaloError) Destroy(value *NachaloError) {
	switch variantValue := value.err.(type) {
	case NachaloErrorBadWords:
		variantValue.destroy()
	case NachaloErrorExpired:
		variantValue.destroy()
	case NachaloErrorPayloadTooLarge:
		variantValue.destroy()
	case NachaloErrorRejected:
		variantValue.destroy()
	case NachaloErrorOutOfRange:
		variantValue.destroy()
	case NachaloErrorRng:
		variantValue.destroy()
	case NachaloErrorOther:
		variantValue.destroy()
	default:
		_ = variantValue
		panic(fmt.Sprintf("invalid error value `%v` in FfiDestroyerNachaloError.Destroy", value))
	}
}

// A named set of defaults and allowed ranges. Profiles are local: devices on different profiles
// interoperate.
type Profile uint

const (
	// Chat or call, both online. The default.
	ProfileInteractive Profile = 1
	// Payloads up to the ceiling, for post-quantum keys and signatures.
	ProfilePqMessenger Profile = 2
	// QR, Bluetooth or LAN, side by side: short TTL, few answers.
	ProfileNearby Profile = 3
)

type FfiConverterProfile struct{}

var FfiConverterProfileINSTANCE = FfiConverterProfile{}

func (c FfiConverterProfile) Lift(rb RustBufferI) Profile {
	return LiftFromRustBuffer[Profile](c, rb)
}

func (c FfiConverterProfile) Lower(value Profile) C.RustBuffer {
	return LowerIntoRustBuffer[Profile](c, value)
}

func (c FfiConverterProfile) LowerExternal(value Profile) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[Profile](c, value))
}
func (FfiConverterProfile) Read(reader io.Reader) Profile {
	id := readInt32(reader)
	return Profile(id)
}

func (FfiConverterProfile) Write(writer io.Writer, value Profile) {
	writeInt32(writer, int32(value))
}

type FfiDestroyerProfile struct{}

func (_ FfiDestroyerProfile) Destroy(value Profile) {
}

// Which side of the handshake a device played.
type Role uint

const (
	// A: sends msg1 and msg3, types the safety words.
	RoleInitiator Role = 1
	// B: sends msg2, shows the safety words.
	RoleResponder Role = 2
)

type FfiConverterRole struct{}

var FfiConverterRoleINSTANCE = FfiConverterRole{}

func (c FfiConverterRole) Lift(rb RustBufferI) Role {
	return LiftFromRustBuffer[Role](c, rb)
}

func (c FfiConverterRole) Lower(value Role) C.RustBuffer {
	return LowerIntoRustBuffer[Role](c, value)
}

func (c FfiConverterRole) LowerExternal(value Role) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[Role](c, value))
}
func (FfiConverterRole) Read(reader io.Reader) Role {
	id := readInt32(reader)
	return Role(id)
}

func (FfiConverterRole) Write(writer io.Writer, value Role) {
	writeInt32(writer, int32(value))
}

type FfiDestroyerRole struct{}

func (_ FfiDestroyerRole) Destroy(value Role) {
}

// Words A draws for an appointment.
func AppointmentWordsA() uint32 {
	return FfiConverterUint32INSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint32_t {
		return C.uniffi_nachalo_uniffi_fn_func_appointment_words_a(_uniffiStatus)
	}))
}

// Words B draws for an appointment.
func AppointmentWordsB() uint32 {
	return FfiConverterUint32INSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint32_t {
		return C.uniffi_nachalo_uniffi_fn_func_appointment_words_b(_uniffiStatus)
	}))
}

// msg1 length, whatever the payload.
func Msg1Len() uint32 {
	return FfiConverterUint32INSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint32_t {
		return C.uniffi_nachalo_uniffi_fn_func_msg1_len(_uniffiStatus)
	}))
}

// msg2 length for a responder payload of `payload` bytes.
func Msg2Len(payload uint32) uint32 {
	return FfiConverterUint32INSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint32_t {
		return C.uniffi_nachalo_uniffi_fn_func_msg2_len(FfiConverterUint32INSTANCE.Lower(payload), _uniffiStatus)
	}))
}

// msg3 length for an initiator payload of `payload` bytes.
func Msg3Len(payload uint32) uint32 {
	return FfiConverterUint32INSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint32_t {
		return C.uniffi_nachalo_uniffi_fn_func_msg3_len(FfiConverterUint32INSTANCE.Lower(payload), _uniffiStatus)
	}))
}

// A new physical token, valid for `lifetime` seconds from `now_unix`. Secret: the returned bytes
// are not zeroized; erase them once the token expires.
func NewPhysicalToken(lifetime uint64, nowUnix uint64) ([]byte, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[*NachaloError](FfiConverterNachaloError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_nachalo_uniffi_fn_func_new_physical_token(FfiConverterUint64INSTANCE.Lower(lifetime), FfiConverterUint64INSTANCE.Lower(nowUnix), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue []byte
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterBytesINSTANCE.Lift(_uniffiRV), nil
	}
}

// Largest payload every receiver accepts.
func PayloadCeiling() uint32 {
	return FfiConverterUint32INSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint32_t {
		return C.uniffi_nachalo_uniffi_fn_func_payload_ceiling(_uniffiStatus)
	}))
}

// Length of `Invitation.rendezvous`.
func RendezvousLen() uint32 {
	return FfiConverterUint32INSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint32_t {
		return C.uniffi_nachalo_uniffi_fn_func_rendezvous_len(_uniffiStatus)
	}))
}

// Length of a physical token.
func TokenLen() uint32 {
	return FfiConverterUint32INSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint32_t {
		return C.uniffi_nachalo_uniffi_fn_func_token_len(_uniffiStatus)
	}))
}

// Words of a live or physical-token invitation.
func WordCount() uint32 {
	return FfiConverterUint32INSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint32_t {
		return C.uniffi_nachalo_uniffi_fn_func_word_count(_uniffiStatus)
	}))
}

// `count` random words from the list, separated by spaces. Secret: the returned string is not
// zeroized.
func Words(count uint32) (string, error) {
	_uniffiRV, _uniffiErr := rustCallWithError[*NachaloError](FfiConverterNachaloError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_nachalo_uniffi_fn_func_words(FfiConverterUint32INSTANCE.Lower(count), _uniffiStatus),
		}
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue string
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterStringINSTANCE.Lift(_uniffiRV), nil
	}
}

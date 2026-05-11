/*
 * FFX-style ZJIT-metadata trampolines for libddwaf leaf functions.
 *
 * Each function is a pair: a naked trampoline registered with Ruby + an impl
 * containing the actual marshalling and libddwaf call. The trampoline body is
 * one inline-asm block that unconditionally branches to the impl, followed by
 * a magic marker, parameter/return type bytes, and the asciz function name.
 * Older Rubies hit the branch and execute the impl normally; ZJIT (Ruby 3.4+)
 * recognises the marker, reads the metadata, and emits a specialised call.
 *
 * When __attribute__((naked)) is unavailable (HAVE_NAKED_ATTRIBUTE not set by
 * extconf.rb), the trampoline degrades to a plain wrapper that calls the
 * impl directly — no marker, no specialisation, but functionally identical.
 *
 * Pattern reference: ~/Code/libraries/ffx/ffx.rb. Type-byte values mirror
 * FFX::TYPES exactly.
 */

#include <ruby.h>
#include <ddwaf.h>
#include <stdbool.h>

#include "trampolines.h"

/* === FFX type-byte constants =========================================== */

#define FFX_BYTE_VOID    0
#define FFX_BYTE_INT     1
#define FFX_BYTE_STRING  3
#define FFX_BYTE_SIZE_T  5
#define FFX_BYTE_DOUBLE  6
#define FFX_BYTE_PTR     8
#define FFX_BYTE_BOOL    9
#define FFX_BYTE_INT64  20
#define FFX_BYTE_UINT64 21

/* Stringify-after-expand: FFX_S(FFX_BYTE_PTR) → "8". */
#define _FFX_S(x) #x
#define FFX_S(x) _FFX_S(x)

#if defined(__aarch64__) || defined(__arm64__)
#  define FFX_BRANCH_INSN "b"
#elif defined(__x86_64__)
#  define FFX_BRANCH_INSN "jmp"
#else
#  error "Unsupported architecture: FFX trampolines need aarch64 or x86_64"
#endif

/* === Per-arity impl-declaration helper =================================
 *
 * IMPL_<N>(name) emits:
 *   - a forward declaration of rb_libddwaf_<name>_impl with an __asm__ rename
 *     that forces the symbol to "_rb_libddwaf_<name>_impl" on every platform
 *     (so the trampoline's branch target is portable);
 *   - the function header (the body follows in user code).
 *
 * The impl is __attribute__((used)) so dead-code elimination won't drop it
 * just because nothing in C source references it (only the asm branch does).
 */

#define IMPL_0(name) \
    static VALUE rb_libddwaf_##name##_impl(VALUE self) \
        __asm__("_rb_libddwaf_" #name "_impl"); \
    __attribute__((used)) \
    static VALUE rb_libddwaf_##name##_impl(VALUE self)

#define IMPL_1(name) \
    static VALUE rb_libddwaf_##name##_impl(VALUE self, VALUE arg0) \
        __asm__("_rb_libddwaf_" #name "_impl"); \
    __attribute__((used)) \
    static VALUE rb_libddwaf_##name##_impl(VALUE self, VALUE arg0)

#define IMPL_2(name) \
    static VALUE rb_libddwaf_##name##_impl(VALUE self, VALUE arg0, VALUE arg1) \
        __asm__("_rb_libddwaf_" #name "_impl"); \
    __attribute__((used)) \
    static VALUE rb_libddwaf_##name##_impl(VALUE self, VALUE arg0, VALUE arg1)

#define IMPL_3(name) \
    static VALUE rb_libddwaf_##name##_impl(VALUE self, VALUE arg0, VALUE arg1, VALUE arg2) \
        __asm__("_rb_libddwaf_" #name "_impl"); \
    __attribute__((used)) \
    static VALUE rb_libddwaf_##name##_impl(VALUE self, VALUE arg0, VALUE arg1, VALUE arg2)

/* === Trampoline macros ================================================= */

#ifdef HAVE_NAKED_ATTRIBUTE

#define FFX_TRAMPOLINE_0(name, ret_byte) \
    __attribute__((naked, aligned(16))) \
    static VALUE rb_libddwaf_##name(VALUE self) \
    { \
        __asm__( \
            FFX_BRANCH_INSN " _rb_libddwaf_" #name "_impl\n" \
            ".long 0x46464930\n" \
            ".byte 0\n" \
            ".byte " FFX_S(ret_byte) "\n" \
            ".asciz \"" #name "\"\n" \
        ); \
    }

#define FFX_TRAMPOLINE_1(name, t0, ret) \
    __attribute__((naked, aligned(16))) \
    static VALUE rb_libddwaf_##name(VALUE self, VALUE arg0) \
    { \
        __asm__( \
            FFX_BRANCH_INSN " _rb_libddwaf_" #name "_impl\n" \
            ".long 0x46464930\n" \
            ".byte 1\n" \
            ".byte " FFX_S(t0) "\n" \
            ".byte " FFX_S(ret) "\n" \
            ".asciz \"" #name "\"\n" \
        ); \
    }

#define FFX_TRAMPOLINE_2(name, t0, t1, ret) \
    __attribute__((naked, aligned(16))) \
    static VALUE rb_libddwaf_##name(VALUE self, VALUE arg0, VALUE arg1) \
    { \
        __asm__( \
            FFX_BRANCH_INSN " _rb_libddwaf_" #name "_impl\n" \
            ".long 0x46464930\n" \
            ".byte 2\n" \
            ".byte " FFX_S(t0) "\n" \
            ".byte " FFX_S(t1) "\n" \
            ".byte " FFX_S(ret) "\n" \
            ".asciz \"" #name "\"\n" \
        ); \
    }

#define FFX_TRAMPOLINE_3(name, t0, t1, t2, ret) \
    __attribute__((naked, aligned(16))) \
    static VALUE rb_libddwaf_##name(VALUE self, VALUE arg0, VALUE arg1, VALUE arg2) \
    { \
        __asm__( \
            FFX_BRANCH_INSN " _rb_libddwaf_" #name "_impl\n" \
            ".long 0x46464930\n" \
            ".byte 3\n" \
            ".byte " FFX_S(t0) "\n" \
            ".byte " FFX_S(t1) "\n" \
            ".byte " FFX_S(t2) "\n" \
            ".byte " FFX_S(ret) "\n" \
            ".asciz \"" #name "\"\n" \
        ); \
    }

#else /* !HAVE_NAKED_ATTRIBUTE — plain wrapper, no asm metadata */

#define FFX_TRAMPOLINE_0(name, ret_byte) \
    static VALUE rb_libddwaf_##name(VALUE self) \
    { return rb_libddwaf_##name##_impl(self); }

#define FFX_TRAMPOLINE_1(name, t0, ret) \
    static VALUE rb_libddwaf_##name(VALUE self, VALUE arg0) \
    { return rb_libddwaf_##name##_impl(self, arg0); }

#define FFX_TRAMPOLINE_2(name, t0, t1, ret) \
    static VALUE rb_libddwaf_##name(VALUE self, VALUE arg0, VALUE arg1) \
    { return rb_libddwaf_##name##_impl(self, arg0, arg1); }

#define FFX_TRAMPOLINE_3(name, t0, t1, t2, ret) \
    static VALUE rb_libddwaf_##name(VALUE self, VALUE arg0, VALUE arg1, VALUE arg2) \
    { return rb_libddwaf_##name##_impl(self, arg0, arg1, arg2); }

#endif

/* === Trampolines ======================================================= */

/* ddwaf_get_version() → const char * (Ruby String) */
IMPL_0(ddwaf_get_version)
{
    (void)self;
    return rb_str_new_cstr(ddwaf_get_version());
}
FFX_TRAMPOLINE_0(ddwaf_get_version, FFX_BYTE_STRING)

/* ddwaf_object_invalid(ddwaf_object*) → ddwaf_object* */
IMPL_1(ddwaf_object_invalid)
{
    (void)self;
    return ULL2NUM((unsigned long long)
        ddwaf_object_invalid((ddwaf_object *)NUM2ULL(arg0)));
}
FFX_TRAMPOLINE_1(ddwaf_object_invalid, FFX_BYTE_PTR, FFX_BYTE_PTR)

/* ddwaf_object_null(ddwaf_object*) → ddwaf_object* */
IMPL_1(ddwaf_object_null)
{
    (void)self;
    return ULL2NUM((unsigned long long)
        ddwaf_object_null((ddwaf_object *)NUM2ULL(arg0)));
}
FFX_TRAMPOLINE_1(ddwaf_object_null, FFX_BYTE_PTR, FFX_BYTE_PTR)

/* ddwaf_object_string(ddwaf_object*, const char *) → ddwaf_object* (NUL-terminated) */
IMPL_2(ddwaf_object_string)
{
    (void)self;
    return ULL2NUM((unsigned long long)
        ddwaf_object_string((ddwaf_object *)NUM2ULL(arg0), StringValueCStr(arg1)));
}
FFX_TRAMPOLINE_2(ddwaf_object_string, FFX_BYTE_PTR, FFX_BYTE_STRING, FFX_BYTE_PTR)

/* ddwaf_object_string_from_unsigned(ddwaf_object*, uint64_t) → ddwaf_object* */
IMPL_2(ddwaf_object_string_from_unsigned)
{
    (void)self;
    return ULL2NUM((unsigned long long)
        ddwaf_object_string_from_unsigned((ddwaf_object *)NUM2ULL(arg0), NUM2ULL(arg1)));
}
FFX_TRAMPOLINE_2(ddwaf_object_string_from_unsigned, FFX_BYTE_PTR, FFX_BYTE_UINT64, FFX_BYTE_PTR)

/* ddwaf_object_string_from_signed(ddwaf_object*, int64_t) → ddwaf_object* */
IMPL_2(ddwaf_object_string_from_signed)
{
    (void)self;
    return ULL2NUM((unsigned long long)
        ddwaf_object_string_from_signed((ddwaf_object *)NUM2ULL(arg0), NUM2LL(arg1)));
}
FFX_TRAMPOLINE_2(ddwaf_object_string_from_signed, FFX_BYTE_PTR, FFX_BYTE_INT64, FFX_BYTE_PTR)

/* ddwaf_object_unsigned(ddwaf_object*, uint64_t) → ddwaf_object* */
IMPL_2(ddwaf_object_unsigned)
{
    (void)self;
    return ULL2NUM((unsigned long long)
        ddwaf_object_unsigned((ddwaf_object *)NUM2ULL(arg0), NUM2ULL(arg1)));
}
FFX_TRAMPOLINE_2(ddwaf_object_unsigned, FFX_BYTE_PTR, FFX_BYTE_UINT64, FFX_BYTE_PTR)

/* ddwaf_object_signed(ddwaf_object*, int64_t) → ddwaf_object* */
IMPL_2(ddwaf_object_signed)
{
    (void)self;
    return ULL2NUM((unsigned long long)
        ddwaf_object_signed((ddwaf_object *)NUM2ULL(arg0), NUM2LL(arg1)));
}
FFX_TRAMPOLINE_2(ddwaf_object_signed, FFX_BYTE_PTR, FFX_BYTE_INT64, FFX_BYTE_PTR)

/* ddwaf_object_bool(ddwaf_object*, bool) → ddwaf_object* */
IMPL_2(ddwaf_object_bool)
{
    (void)self;
    return ULL2NUM((unsigned long long)
        ddwaf_object_bool((ddwaf_object *)NUM2ULL(arg0), RTEST(arg1) ? true : false));
}
FFX_TRAMPOLINE_2(ddwaf_object_bool, FFX_BYTE_PTR, FFX_BYTE_BOOL, FFX_BYTE_PTR)

/* ddwaf_object_float(ddwaf_object*, double) → ddwaf_object* */
IMPL_2(ddwaf_object_float)
{
    (void)self;
    return ULL2NUM((unsigned long long)
        ddwaf_object_float((ddwaf_object *)NUM2ULL(arg0), NUM2DBL(arg1)));
}
FFX_TRAMPOLINE_2(ddwaf_object_float, FFX_BYTE_PTR, FFX_BYTE_DOUBLE, FFX_BYTE_PTR)

/* ddwaf_object_array(ddwaf_object*) → ddwaf_object* */
IMPL_1(ddwaf_object_array)
{
    (void)self;
    return ULL2NUM((unsigned long long)
        ddwaf_object_array((ddwaf_object *)NUM2ULL(arg0)));
}
FFX_TRAMPOLINE_1(ddwaf_object_array, FFX_BYTE_PTR, FFX_BYTE_PTR)

/* ddwaf_object_map(ddwaf_object*) → ddwaf_object* */
IMPL_1(ddwaf_object_map)
{
    (void)self;
    return ULL2NUM((unsigned long long)
        ddwaf_object_map((ddwaf_object *)NUM2ULL(arg0)));
}
FFX_TRAMPOLINE_1(ddwaf_object_map, FFX_BYTE_PTR, FFX_BYTE_PTR)

/* ddwaf_object_array_add(ddwaf_object*, ddwaf_object*) → bool */
IMPL_2(ddwaf_object_array_add)
{
    (void)self;
    bool r = ddwaf_object_array_add((ddwaf_object *)NUM2ULL(arg0), (ddwaf_object *)NUM2ULL(arg1));
    return r ? Qtrue : Qfalse;
}
FFX_TRAMPOLINE_2(ddwaf_object_array_add, FFX_BYTE_PTR, FFX_BYTE_PTR, FFX_BYTE_BOOL)

/* ddwaf_object_map_add(ddwaf_object*, const char *, ddwaf_object*) → bool (NUL-terminated key) */
IMPL_3(ddwaf_object_map_add)
{
    (void)self;
    bool r = ddwaf_object_map_add(
        (ddwaf_object *)NUM2ULL(arg0),
        StringValueCStr(arg1),
        (ddwaf_object *)NUM2ULL(arg2));
    return r ? Qtrue : Qfalse;
}
FFX_TRAMPOLINE_3(ddwaf_object_map_add, FFX_BYTE_PTR, FFX_BYTE_STRING, FFX_BYTE_PTR, FFX_BYTE_BOOL)

/* ddwaf_object_size(const ddwaf_object*) → size_t */
IMPL_1(ddwaf_object_size)
{
    (void)self;
    return SIZET2NUM(ddwaf_object_size((ddwaf_object *)NUM2ULL(arg0)));
}
FFX_TRAMPOLINE_1(ddwaf_object_size, FFX_BYTE_PTR, FFX_BYTE_SIZE_T)

/* ddwaf_object_length(const ddwaf_object*) → size_t */
IMPL_1(ddwaf_object_length)
{
    (void)self;
    return SIZET2NUM(ddwaf_object_length((ddwaf_object *)NUM2ULL(arg0)));
}
FFX_TRAMPOLINE_1(ddwaf_object_length, FFX_BYTE_PTR, FFX_BYTE_SIZE_T)

/* ddwaf_object_get_unsigned(const ddwaf_object*) → uint64 */
IMPL_1(ddwaf_object_get_unsigned)
{
    (void)self;
    return ULL2NUM(ddwaf_object_get_unsigned((ddwaf_object *)NUM2ULL(arg0)));
}
FFX_TRAMPOLINE_1(ddwaf_object_get_unsigned, FFX_BYTE_PTR, FFX_BYTE_UINT64)

/* ddwaf_object_get_signed(const ddwaf_object*) → int64 */
IMPL_1(ddwaf_object_get_signed)
{
    (void)self;
    return LL2NUM(ddwaf_object_get_signed((ddwaf_object *)NUM2ULL(arg0)));
}
FFX_TRAMPOLINE_1(ddwaf_object_get_signed, FFX_BYTE_PTR, FFX_BYTE_INT64)

/* ddwaf_object_get_bool(const ddwaf_object*) → bool */
IMPL_1(ddwaf_object_get_bool)
{
    (void)self;
    return ddwaf_object_get_bool((ddwaf_object *)NUM2ULL(arg0)) ? Qtrue : Qfalse;
}
FFX_TRAMPOLINE_1(ddwaf_object_get_bool, FFX_BYTE_PTR, FFX_BYTE_BOOL)

/* ddwaf_object_get_float(const ddwaf_object*) → double */
IMPL_1(ddwaf_object_get_float)
{
    (void)self;
    return DBL2NUM(ddwaf_object_get_float((ddwaf_object *)NUM2ULL(arg0)));
}
FFX_TRAMPOLINE_1(ddwaf_object_get_float, FFX_BYTE_PTR, FFX_BYTE_DOUBLE)

/* ddwaf_object_get_index(const ddwaf_object*, size_t) → const ddwaf_object* */
IMPL_2(ddwaf_object_get_index)
{
    (void)self;
    return ULL2NUM((unsigned long long)
        ddwaf_object_get_index((ddwaf_object *)NUM2ULL(arg0), NUM2SIZET(arg1)));
}
FFX_TRAMPOLINE_2(ddwaf_object_get_index, FFX_BYTE_PTR, FFX_BYTE_SIZE_T, FFX_BYTE_PTR)

/* === Plain cfuncs (binary-string / non-trivial signatures) ============ */

/* ddwaf_object_stringl: ptr-as-Integer + Ruby String + byte length → ptr-as-Integer.
 * Cannot be a pure trampoline because FFX has no "Ruby String bytes pointer"
 * type byte — RSTRING_PTR extraction happens inline. Loses ZJIT specialisation. */
static VALUE
rb_libddwaf_ddwaf_object_stringl(VALUE self, VALUE obj, VALUE str, VALUE len)
{
    (void)self;
    StringValue(str);
    return ULL2NUM((unsigned long long) ddwaf_object_stringl(
        (ddwaf_object *)NUM2ULL(obj),
        RSTRING_PTR(str),
        NUM2SIZET(len)));
}

static VALUE
rb_libddwaf_ddwaf_object_map_addl(VALUE self, VALUE obj, VALUE key, VALUE keylen, VALUE child)
{
    (void)self;
    StringValue(key);
    bool r = ddwaf_object_map_addl(
        (ddwaf_object *)NUM2ULL(obj),
        RSTRING_PTR(key),
        NUM2SIZET(keylen),
        (ddwaf_object *)NUM2ULL(child));
    return r ? Qtrue : Qfalse;
}

/* === Registration ===================================================== */

void
libddwaf_register_trampolines(VALUE target_module)
{
#define REG(name, argc) \
    rb_define_module_function(target_module, #name, rb_libddwaf_##name, argc)

    REG(ddwaf_get_version, 0);
    REG(ddwaf_object_invalid, 1);
    REG(ddwaf_object_null, 1);
    REG(ddwaf_object_string, 2);
    REG(ddwaf_object_string_from_unsigned, 2);
    REG(ddwaf_object_string_from_signed, 2);
    REG(ddwaf_object_unsigned, 2);
    REG(ddwaf_object_signed, 2);
    REG(ddwaf_object_bool, 2);
    REG(ddwaf_object_float, 2);
    REG(ddwaf_object_array, 1);
    REG(ddwaf_object_map, 1);
    REG(ddwaf_object_array_add, 2);
    REG(ddwaf_object_map_add, 3);
    REG(ddwaf_object_size, 1);
    REG(ddwaf_object_length, 1);
    REG(ddwaf_object_get_unsigned, 1);
    REG(ddwaf_object_get_signed, 1);
    REG(ddwaf_object_get_bool, 1);
    REG(ddwaf_object_get_float, 1);
    REG(ddwaf_object_get_index, 2);

    REG(ddwaf_object_stringl, 3);
    REG(ddwaf_object_map_addl, 4);

#undef REG
}

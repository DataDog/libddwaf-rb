/*
 * Datadog libddwaf Ruby C extension.
 *
 * Phase 1: scaffold + linked-version sanity constant.
 * Phase 2: LibDDWAF module + integer constants + internal enum tables.
 * Phase 3: LibDDWAF::{Object,Handle,Builder,Context} TypedData wrappers.
 *
 * Subsequent phases populate the wrappers with FFX-style trampolines for
 * primitive leaf functions, and plain cfuncs for the converter, the
 * GVL-releasing ddwaf_run path, and the log callback.
 */

#include <ruby.h>
#include <ruby/thread.h>
#include <ddwaf.h>
#include <stdbool.h>
#include <stddef.h>

#include "trampolines.h"

/* === Enum tables (Phase 2) ============================================== */

typedef struct {
    const char *name;
    long value;
    VALUE symbol;
} libddwaf_enum_entry;

static libddwaf_enum_entry obj_type_table[] = {
    {"ddwaf_obj_invalid",  DDWAF_OBJ_INVALID,  Qundef},
    {"ddwaf_obj_signed",   DDWAF_OBJ_SIGNED,   Qundef},
    {"ddwaf_obj_unsigned", DDWAF_OBJ_UNSIGNED, Qundef},
    {"ddwaf_obj_string",   DDWAF_OBJ_STRING,   Qundef},
    {"ddwaf_obj_array",    DDWAF_OBJ_ARRAY,    Qundef},
    {"ddwaf_obj_map",      DDWAF_OBJ_MAP,      Qundef},
    {"ddwaf_obj_bool",     DDWAF_OBJ_BOOL,     Qundef},
    {"ddwaf_obj_float",    DDWAF_OBJ_FLOAT,    Qundef},
    {"ddwaf_obj_null",     DDWAF_OBJ_NULL,     Qundef},
};

static libddwaf_enum_entry ret_code_table[] = {
    {"ddwaf_err_internal",         DDWAF_ERR_INTERNAL,         Qundef},
    {"ddwaf_err_invalid_object",   DDWAF_ERR_INVALID_OBJECT,   Qundef},
    {"ddwaf_err_invalid_argument", DDWAF_ERR_INVALID_ARGUMENT, Qundef},
    {"ddwaf_ok",                   DDWAF_OK,                   Qundef},
    {"ddwaf_match",                DDWAF_MATCH,                Qundef},
};

static libddwaf_enum_entry log_level_table[] = {
    {"ddwaf_log_trace", DDWAF_LOG_TRACE, Qundef},
    {"ddwaf_log_debug", DDWAF_LOG_DEBUG, Qundef},
    {"ddwaf_log_info",  DDWAF_LOG_INFO,  Qundef},
    {"ddwaf_log_warn",  DDWAF_LOG_WARN,  Qundef},
    {"ddwaf_log_error", DDWAF_LOG_ERROR, Qundef},
    {"ddwaf_log_off",   DDWAF_LOG_OFF,   Qundef},
};

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

static void
init_enum_table(libddwaf_enum_entry *table, size_t size)
{
    size_t i;
    for (i = 0; i < size; i++) {
        table[i].symbol = ID2SYM(rb_intern(table[i].name));
    }
}

static VALUE
enum_int_to_sym(long value, libddwaf_enum_entry *table, size_t size)
{
    size_t i;
    for (i = 0; i < size; i++) {
        if (table[i].value == value) return table[i].symbol;
    }
    return LONG2NUM(value);
}

/* File-scope class VALUEs, populated in Init. Used by cfuncs that need to
 * construct or unwrap TypedData instances outside Init's scope. */
static VALUE rb_cNative_Object;
static VALUE rb_cNative_Handle;
static VALUE rb_cNative_Builder;
static VALUE rb_cNative_Context;

/* === Object TypedData wrapper =========================================== */

typedef struct {
    ddwaf_object *obj;
    VALUE parent;   /* Qnil for owned; parent VALUE for borrowed children */
    bool owned;     /* true means dfree calls ddwaf_object_free + xfree(obj) */
} obj_data_t;

static void
obj_data_mark(void *ptr)
{
    obj_data_t *d = (obj_data_t *)ptr;
    rb_gc_mark(d->parent);
}

static void
obj_data_free(void *ptr)
{
    obj_data_t *d = (obj_data_t *)ptr;
    if (d->owned && d->obj != NULL) {
        ddwaf_object_free(d->obj);
        xfree(d->obj);
    }
    xfree(d);
}

static size_t
obj_data_size(const void *ptr)
{
    const obj_data_t *d = (const obj_data_t *)ptr;
    return sizeof(*d) + (d->owned && d->obj ? sizeof(*d->obj) : 0);
}

static const rb_data_type_t obj_data_type = {
    .wrap_struct_name = "Datadog::AppSec::WAF::LibDDWAF::Object",
    .function = {
        .dmark = obj_data_mark,
        .dfree = obj_data_free,
        .dsize = obj_data_size,
    },
    .flags = RUBY_TYPED_FREE_IMMEDIATELY,
};

static VALUE
obj_alloc(VALUE klass)
{
    obj_data_t *d;
    VALUE wrapper = TypedData_Make_Struct(klass, obj_data_t, &obj_data_type, d);
    d->obj = ZALLOC(ddwaf_object);
    d->parent = Qnil;
    d->owned = true;
    return wrapper;
}

/* Internal: borrow a child pointer from a parent. Not exposed to Ruby. */
static VALUE
obj_borrow(VALUE klass, ddwaf_object *target, VALUE parent)
{
    obj_data_t *d;
    VALUE wrapper = TypedData_Make_Struct(klass, obj_data_t, &obj_data_type, d);
    d->obj = target;
    d->parent = parent;
    d->owned = false;
    return wrapper;
}

static ddwaf_object *
obj_unwrap(VALUE self)
{
    obj_data_t *d;
    TypedData_Get_Struct(self, obj_data_t, &obj_data_type, d);
    return d->obj;
}

static void
obj_require_type(ddwaf_object *obj, DDWAF_OBJ_TYPE expected, const char *accessor)
{
    if (obj->type == expected) return;
    rb_raise(rb_eTypeError, "%s called on ddwaf_object of type %d", accessor, (int)obj->type);
}

/* obj.type → Symbol */
static VALUE
obj_method_type(VALUE self)
{
    long v = obj_unwrap(self)->type;
    size_t i;
    for (i = 0; i < ARRAY_SIZE(obj_type_table); i++) {
        if (obj_type_table[i].value == v) return obj_type_table[i].symbol;
    }
    return LONG2NUM(v);
}

/* obj.nb_entries → Integer */
static VALUE
obj_method_nb_entries(VALUE self)
{
    return ULL2NUM(obj_unwrap(self)->nbEntries);
}

/* obj.string_bytes → binary String */
static VALUE
obj_method_string_bytes(VALUE self)
{
    ddwaf_object *obj = obj_unwrap(self);
    obj_require_type(obj, DDWAF_OBJ_STRING, "string_bytes");
    return rb_str_new(obj->stringValue, (long)obj->nbEntries);
}

/* obj.unsigned_value → Integer (uint64) */
static VALUE
obj_method_unsigned_value(VALUE self)
{
    ddwaf_object *obj = obj_unwrap(self);
    obj_require_type(obj, DDWAF_OBJ_UNSIGNED, "unsigned_value");
    return ULL2NUM(obj->uintValue);
}

/* obj.signed_value → Integer (int64) */
static VALUE
obj_method_signed_value(VALUE self)
{
    ddwaf_object *obj = obj_unwrap(self);
    obj_require_type(obj, DDWAF_OBJ_SIGNED, "signed_value");
    return LL2NUM(obj->intValue);
}

/* obj.bool_value → true/false */
static VALUE
obj_method_bool_value(VALUE self)
{
    ddwaf_object *obj = obj_unwrap(self);
    obj_require_type(obj, DDWAF_OBJ_BOOL, "bool_value");
    return obj->boolean ? Qtrue : Qfalse;
}

/* obj.float_value → Float */
static VALUE
obj_method_float_value(VALUE self)
{
    ddwaf_object *obj = obj_unwrap(self);
    obj_require_type(obj, DDWAF_OBJ_FLOAT, "float_value");
    return DBL2NUM(obj->f64);
}

/* obj.array_index(i) → Object (borrowed). Works for arrays AND maps. */
static VALUE
obj_method_array_index(VALUE self, VALUE idx)
{
    ddwaf_object *obj = obj_unwrap(self);
    if (obj->type != DDWAF_OBJ_ARRAY && obj->type != DDWAF_OBJ_MAP) {
        rb_raise(rb_eTypeError, "array_index called on ddwaf_object of type %d", (int)obj->type);
    }
    long i = NUM2LONG(idx);
    if (i < 0 || (uint64_t)i >= obj->nbEntries) {
        rb_raise(rb_eIndexError, "index %ld out of range (size=%llu)", i, (unsigned long long)obj->nbEntries);
    }
    return obj_borrow(rb_obj_class(self), &obj->array[i], self);
}

/* obj.key_bytes → binary String of parameterName, or nil. Used for map entries. */
static VALUE
obj_method_key_bytes(VALUE self)
{
    ddwaf_object *obj = obj_unwrap(self);
    if (obj->parameterName == NULL) return Qnil;
    return rb_str_new(obj->parameterName, (long)obj->parameterNameLength);
}

/* obj.truncated? — Ruby-side flag, not in libddwaf. */
static VALUE
obj_method_truncated_p(VALUE self)
{
    return RTEST(rb_attr_get(self, rb_intern("@truncated"))) ? Qtrue : Qfalse;
}

/* obj.mark_truncated! — mutates self by setting @truncated. */
static VALUE
obj_method_mark_truncated_bang(VALUE self)
{
    rb_iv_set(self, "@truncated", Qtrue);
    return Qtrue;
}

/* obj.object_ptr → Integer. Returns the underlying ddwaf_object* as ULL so
 * Ruby callers can pass it to the LibDDWAF trampolines. */
static VALUE
obj_method_object_ptr(VALUE self)
{
    obj_data_t *d;
    TypedData_Get_Struct(self, obj_data_t, &obj_data_type, d);
    return ULL2NUM((unsigned long long)d->obj);
}

/* obj.owned? → true if dfree will free the payload. */
static VALUE
obj_method_owned_p(VALUE self)
{
    obj_data_t *d;
    TypedData_Get_Struct(self, obj_data_t, &obj_data_type, d);
    return d->owned ? Qtrue : Qfalse;
}

/* obj.disown! — mark self as non-owning so dfree skips ddwaf_object_free.
 * Call after a successful array_add/map_add* that transferred the payload
 * to a parent. The struct memory is still freed by dfree (xfree); only the
 * recursive ddwaf_object_free is skipped. */
static VALUE
obj_method_disown_bang(VALUE self)
{
    obj_data_t *d;
    TypedData_Get_Struct(self, obj_data_t, &obj_data_type, d);
    d->owned = false;
    return self;
}

/* === Handle TypedData wrapper =========================================== */

typedef struct {
    ddwaf_handle handle;
} handle_data_t;

static void
handle_data_free(void *ptr)
{
    handle_data_t *d = (handle_data_t *)ptr;
    if (d->handle != NULL) ddwaf_destroy(d->handle);
    xfree(d);
}

static const rb_data_type_t handle_data_type = {
    .wrap_struct_name = "Datadog::AppSec::WAF::LibDDWAF::Handle",
    .function = {.dfree = handle_data_free},
    .flags = RUBY_TYPED_FREE_IMMEDIATELY,
};

/* === Builder TypedData wrapper ========================================== */

typedef struct {
    ddwaf_builder builder;
} builder_data_t;

static void
builder_data_free(void *ptr)
{
    builder_data_t *d = (builder_data_t *)ptr;
    if (d->builder != NULL) ddwaf_builder_destroy(d->builder);
    xfree(d);
}

static const rb_data_type_t builder_data_type = {
    .wrap_struct_name = "Datadog::AppSec::WAF::LibDDWAF::Builder",
    .function = {.dfree = builder_data_free},
    .flags = RUBY_TYPED_FREE_IMMEDIATELY,
};

/* === Context TypedData wrapper ========================================== */

typedef struct {
    ddwaf_context context;
} context_data_t;

static void
context_data_free(void *ptr)
{
    context_data_t *d = (context_data_t *)ptr;
    if (d->context != NULL) ddwaf_context_destroy(d->context);
    xfree(d);
}

static const rb_data_type_t context_data_type = {
    .wrap_struct_name = "Datadog::AppSec::WAF::LibDDWAF::Context",
    .function = {.dfree = context_data_free},
    .flags = RUBY_TYPED_FREE_IMMEDIATELY,
};

/* === Wrap/unwrap helpers ============================================== */

static VALUE
handle_wrap(ddwaf_handle h)
{
    handle_data_t *d;
    VALUE w = TypedData_Make_Struct(rb_cNative_Handle, handle_data_t, &handle_data_type, d);
    d->handle = h;
    return w;
}

static ddwaf_handle
handle_unwrap(VALUE wrapper)
{
    handle_data_t *d;
    TypedData_Get_Struct(wrapper, handle_data_t, &handle_data_type, d);
    if (d->handle == NULL) rb_raise(rb_eRuntimeError, "LibDDWAF::Handle has been destroyed");
    return d->handle;
}

static VALUE
builder_wrap(ddwaf_builder b)
{
    builder_data_t *d;
    VALUE w = TypedData_Make_Struct(rb_cNative_Builder, builder_data_t, &builder_data_type, d);
    d->builder = b;
    return w;
}

static ddwaf_builder
builder_unwrap(VALUE wrapper)
{
    builder_data_t *d;
    TypedData_Get_Struct(wrapper, builder_data_t, &builder_data_type, d);
    if (d->builder == NULL) rb_raise(rb_eRuntimeError, "LibDDWAF::Builder has been destroyed");
    return d->builder;
}

static VALUE
context_wrap(ddwaf_context c)
{
    context_data_t *d;
    VALUE w = TypedData_Make_Struct(rb_cNative_Context, context_data_t, &context_data_type, d);
    d->context = c;
    return w;
}

static ddwaf_context
context_unwrap(VALUE wrapper)
{
    context_data_t *d;
    TypedData_Get_Struct(wrapper, context_data_t, &context_data_type, d);
    if (d->context == NULL) rb_raise(rb_eRuntimeError, "LibDDWAF::Context has been destroyed");
    return d->context;
}

/* === Object cfuncs (non-trampoline) =================================== */

/* ddwaf_object_type(ptr) → Symbol via obj_type_table. Plain cfunc because
 * Symbol return isn't expressible in FFX type bytes. Takes pointer-as-Integer
 * like the Phase 4 trampolines (caller passes `obj.object_ptr`). */
static VALUE
rb_libddwaf_ddwaf_object_type(VALUE self, VALUE arg0)
{
    (void)self;
    return enum_int_to_sym(((ddwaf_object *)NUM2ULL(arg0))->type,
                           obj_type_table, ARRAY_SIZE(obj_type_table));
}

/* === Lifecycle cfuncs ================================================= */

/* ddwaf_builder_init(config_hash) → LibDDWAF::Builder | nil.
 *
 * config_hash shape (all keys optional; defaults from <ddwaf.h> caps):
 *   {
 *     limits:     { max_container_size: 256, max_container_depth: 20, max_string_length: 4096 },
 *     obfuscator: { key_regex: "...", value_regex: "..." },
 *   }
 *
 * `free_fn` is left NULL — libddwaf will not free the ddwaf_objects we pass
 * to `add_or_update_config` or `ddwaf_run`. Our `LibDDWAF::Object` wrapper
 * frees the payload via `ddwaf_object_free` from its dfree on GC. Callers
 * that pass persistent data to `ddwaf_run` must retain a Ruby reference to
 * the wrapper until the context is destroyed (libddwaf stores pointers into
 * the persistent payload). */
static VALUE
rb_libddwaf_ddwaf_builder_init(VALUE self, VALUE rb_config)
{
    (void)self;
    ddwaf_config cfg = {0};
    cfg.limits.max_container_size  = DDWAF_MAX_CONTAINER_SIZE;
    cfg.limits.max_container_depth = DDWAF_MAX_CONTAINER_DEPTH;
    cfg.limits.max_string_length   = DDWAF_MAX_STRING_LENGTH;
    cfg.free_fn = NULL;

    if (RB_TYPE_P(rb_config, T_HASH)) {
        VALUE limits = rb_hash_aref(rb_config, ID2SYM(rb_intern("limits")));
        if (RB_TYPE_P(limits, T_HASH)) {
            VALUE v;
            v = rb_hash_aref(limits, ID2SYM(rb_intern("max_container_size")));
            if (!NIL_P(v)) cfg.limits.max_container_size  = NUM2UINT(v);
            v = rb_hash_aref(limits, ID2SYM(rb_intern("max_container_depth")));
            if (!NIL_P(v)) cfg.limits.max_container_depth = NUM2UINT(v);
            v = rb_hash_aref(limits, ID2SYM(rb_intern("max_string_length")));
            if (!NIL_P(v)) cfg.limits.max_string_length   = NUM2UINT(v);
        }
        VALUE obf = rb_hash_aref(rb_config, ID2SYM(rb_intern("obfuscator")));
        if (RB_TYPE_P(obf, T_HASH)) {
            VALUE v;
            v = rb_hash_aref(obf, ID2SYM(rb_intern("key_regex")));
            if (!NIL_P(v)) cfg.obfuscator.key_regex   = StringValueCStr(v);
            v = rb_hash_aref(obf, ID2SYM(rb_intern("value_regex")));
            if (!NIL_P(v)) cfg.obfuscator.value_regex = StringValueCStr(v);
        }
    }

    ddwaf_builder b = ddwaf_builder_init(&cfg);
    if (b == NULL) return Qnil;
    return builder_wrap(b);
}

/* Explicit destroyers — idempotent, null out the wrapper's pointer so the
 * GC-time dfree skips the libddwaf destroy call. Useful for tests and for
 * resource cleanup at known points. */

static VALUE
rb_libddwaf_ddwaf_builder_destroy(VALUE self, VALUE wrapper)
{
    (void)self;
    builder_data_t *d;
    TypedData_Get_Struct(wrapper, builder_data_t, &builder_data_type, d);
    if (d->builder != NULL) {
        ddwaf_builder_destroy(d->builder);
        d->builder = NULL;
    }
    return Qnil;
}

static VALUE
rb_libddwaf_ddwaf_destroy(VALUE self, VALUE wrapper)
{
    (void)self;
    handle_data_t *d;
    TypedData_Get_Struct(wrapper, handle_data_t, &handle_data_type, d);
    if (d->handle != NULL) {
        ddwaf_destroy(d->handle);
        d->handle = NULL;
    }
    return Qnil;
}

static VALUE
rb_libddwaf_ddwaf_context_destroy(VALUE self, VALUE wrapper)
{
    (void)self;
    context_data_t *d;
    TypedData_Get_Struct(wrapper, context_data_t, &context_data_type, d);
    if (d->context != NULL) {
        ddwaf_context_destroy(d->context);
        d->context = NULL;
    }
    return Qnil;
}

static VALUE
rb_libddwaf_ddwaf_context_init(VALUE self, VALUE handle_w)
{
    (void)self;
    ddwaf_context c = ddwaf_context_init(handle_unwrap(handle_w));
    if (c == NULL) return Qnil;
    return context_wrap(c);
}

static VALUE
rb_libddwaf_ddwaf_builder_build_instance(VALUE self, VALUE builder_w)
{
    (void)self;
    ddwaf_handle h = ddwaf_builder_build_instance(builder_unwrap(builder_w));
    if (h == NULL) return Qnil;
    return handle_wrap(h);
}

static VALUE
rb_libddwaf_ddwaf_builder_add_or_update_config(VALUE self, VALUE builder_w, VALUE key, VALUE config_w, VALUE diag_w)
{
    (void)self;
    ddwaf_builder b = builder_unwrap(builder_w);
    StringValue(key);
    bool r = ddwaf_builder_add_or_update_config(
        b,
        RSTRING_PTR(key),
        (size_t)RSTRING_LEN(key),
        obj_unwrap(config_w),
        obj_unwrap(diag_w));
    return r ? Qtrue : Qfalse;
}

static VALUE
rb_libddwaf_ddwaf_builder_remove_config(VALUE self, VALUE builder_w, VALUE path)
{
    (void)self;
    StringValue(path);
    bool r = ddwaf_builder_remove_config(
        builder_unwrap(builder_w),
        RSTRING_PTR(path),
        (size_t)RSTRING_LEN(path));
    return r ? Qtrue : Qfalse;
}

/* ddwaf_known_addresses(handle) → Array<String>. libddwaf returns a NUL-terminated
 * string array + count via a uint32_t out-param. We materialise to a Ruby
 * Array of frozen Strings — caller-friendly than exposing the raw pointer. */
static VALUE
rb_libddwaf_ddwaf_known_addresses(VALUE self, VALUE handle_w)
{
    (void)self;
    uint32_t count = 0;
    const char *const *list = ddwaf_known_addresses(handle_unwrap(handle_w), &count);
    if (list == NULL || count == 0) return rb_ary_new();

    VALUE result = rb_ary_new_capa((long)count);
    for (uint32_t i = 0; i < count; i++) {
        rb_ary_push(result, rb_str_new_cstr(list[i]));
    }
    return result;
}

/* ddwaf_run with GVL release. Per <ddwaf.h>, this can take up to `timeout_us`
 * microseconds and parsing input on a long ruleset is real CPU work — must
 * not freeze the VM in a threaded web server. Args are unwrapped to C
 * pointers BEFORE entering the no-GVL block (no VALUE access inside). */
struct ddwaf_run_args {
    ddwaf_context context;
    ddwaf_object *persistent;
    ddwaf_object *ephemeral;
    ddwaf_object *result;
    uint64_t timeout;
    DDWAF_RET_CODE ret;
};

static void *
ddwaf_run_no_gvl(void *raw)
{
    struct ddwaf_run_args *a = (struct ddwaf_run_args *)raw;
    a->ret = ddwaf_run(a->context, a->persistent, a->ephemeral, a->result, a->timeout);
    return NULL;
}

static VALUE
rb_libddwaf_ddwaf_run(VALUE self, VALUE ctx_w, VALUE pers_w, VALUE eph_w, VALUE res_w, VALUE timeout_v)
{
    (void)self;
    struct ddwaf_run_args args = {
        context_unwrap(ctx_w),
        obj_unwrap(pers_w),
        obj_unwrap(eph_w),
        obj_unwrap(res_w),
        NUM2ULL(timeout_v),
        DDWAF_OK,
    };
    rb_thread_call_without_gvl(ddwaf_run_no_gvl, &args, NULL, NULL);
    return enum_int_to_sym(args.ret, ret_code_table, ARRAY_SIZE(ret_code_table));
}

/* === Init =============================================================== */

void
Init_libddwaf_ext(void)
{
    VALUE rb_mDatadog  = rb_define_module("Datadog");
    VALUE rb_mAppSec   = rb_define_module_under(rb_mDatadog, "AppSec");
    VALUE rb_mWAF      = rb_define_module_under(rb_mAppSec, "WAF");
    VALUE rb_mNative   = rb_define_module_under(rb_mWAF, "LibDDWAF");

    rb_define_const(rb_mNative, "LIBDDWAF_LINKED_VERSION", rb_str_new_cstr(ddwaf_get_version()));

    /* True when the build emitted FFX-style trampolines (with ZJIT metadata),
     * false when extconf.rb's __attribute__((naked)) probe failed and the
     * fallback plain-wrapper path was used. Specs and bench tools key off
     * this to decide whether to assert / report ZJIT-relevant behaviour. */
#ifdef HAVE_NAKED_ATTRIBUTE
    rb_define_const(rb_mNative, "TRAMPOLINES", Qtrue);
#else
    rb_define_const(rb_mNative, "TRAMPOLINES", Qfalse);
#endif

    /* Integer constants on LibDDWAF. DEFAULT_* are Ruby-side converter
     * defaults; DDWAF_MAX_* are libddwaf's compiled-in caps (the Ruby
     * defaults intentionally allow more headroom — see findings §5). */
    rb_define_const(rb_mNative, "DEFAULT_MAX_CONTAINER_SIZE",  INT2FIX(256));
    rb_define_const(rb_mNative, "DEFAULT_MAX_CONTAINER_DEPTH", INT2FIX(20));
    rb_define_const(rb_mNative, "DEFAULT_MAX_STRING_LENGTH",   INT2FIX(16384));
    rb_define_const(rb_mNative, "DDWAF_MAX_CONTAINER_SIZE",    INT2FIX(DDWAF_MAX_CONTAINER_SIZE));
    rb_define_const(rb_mNative, "DDWAF_MAX_CONTAINER_DEPTH",   INT2FIX(DDWAF_MAX_CONTAINER_DEPTH));
    rb_define_const(rb_mNative, "DDWAF_MAX_STRING_LENGTH",     INT2FIX(DDWAF_MAX_STRING_LENGTH));
    rb_define_const(rb_mNative, "DDWAF_RUN_TIMEOUT",           INT2FIX(DDWAF_RUN_TIMEOUT));

    /* LibDDWAF::Object: TypedData wrapper around ddwaf_object. */
    rb_cNative_Object = rb_define_class_under(rb_mNative, "Object", rb_cObject);
    rb_define_alloc_func(rb_cNative_Object, obj_alloc);
    rb_define_method(rb_cNative_Object, "type",            obj_method_type,            0);
    rb_define_method(rb_cNative_Object, "nb_entries",      obj_method_nb_entries,      0);
    rb_define_method(rb_cNative_Object, "string_bytes",    obj_method_string_bytes,    0);
    rb_define_method(rb_cNative_Object, "unsigned_value",  obj_method_unsigned_value,  0);
    rb_define_method(rb_cNative_Object, "signed_value",    obj_method_signed_value,    0);
    rb_define_method(rb_cNative_Object, "bool_value",      obj_method_bool_value,      0);
    rb_define_method(rb_cNative_Object, "float_value",     obj_method_float_value,     0);
    rb_define_method(rb_cNative_Object, "array_index",     obj_method_array_index,     1);
    rb_define_method(rb_cNative_Object, "key_bytes",       obj_method_key_bytes,       0);
    rb_define_method(rb_cNative_Object, "truncated?",      obj_method_truncated_p,     0);
    rb_define_method(rb_cNative_Object, "mark_truncated!", obj_method_mark_truncated_bang, 0);
    rb_define_method(rb_cNative_Object, "object_ptr",      obj_method_object_ptr,      0);
    rb_define_method(rb_cNative_Object, "owned?",          obj_method_owned_p,         0);
    rb_define_method(rb_cNative_Object, "disown!",         obj_method_disown_bang,     0);

    /* LibDDWAF::{Handle,Builder,Context}: opaque-pointer wrappers. Ruby can't
     * `new` them — undef the allocator. Constructed internally by
     * ddwaf_builder_init / _build_instance / _context_init. */
    rb_cNative_Handle  = rb_define_class_under(rb_mNative, "Handle",  rb_cObject);
    rb_cNative_Builder = rb_define_class_under(rb_mNative, "Builder", rb_cObject);
    rb_cNative_Context = rb_define_class_under(rb_mNative, "Context", rb_cObject);
    rb_undef_alloc_func(rb_cNative_Handle);
    rb_undef_alloc_func(rb_cNative_Builder);
    rb_undef_alloc_func(rb_cNative_Context);

    init_enum_table(obj_type_table,  ARRAY_SIZE(obj_type_table));
    init_enum_table(ret_code_table,  ARRAY_SIZE(ret_code_table));
    init_enum_table(log_level_table, ARRAY_SIZE(log_level_table));

    libddwaf_register_trampolines(rb_mNative);

    /* Phase 6 cfuncs (non-trampoline): Symbol-returning enum reads, lifecycle,
     * GVL-releasing run. */
    rb_define_module_function(rb_mNative, "ddwaf_object_type",                   rb_libddwaf_ddwaf_object_type, 1);
    rb_define_module_function(rb_mNative, "ddwaf_builder_init",                  rb_libddwaf_ddwaf_builder_init, 1);
    rb_define_module_function(rb_mNative, "ddwaf_builder_destroy",               rb_libddwaf_ddwaf_builder_destroy, 1);
    rb_define_module_function(rb_mNative, "ddwaf_builder_build_instance",        rb_libddwaf_ddwaf_builder_build_instance, 1);
    rb_define_module_function(rb_mNative, "ddwaf_builder_add_or_update_config",  rb_libddwaf_ddwaf_builder_add_or_update_config, 4);
    rb_define_module_function(rb_mNative, "ddwaf_builder_remove_config",         rb_libddwaf_ddwaf_builder_remove_config, 2);
    rb_define_module_function(rb_mNative, "ddwaf_known_addresses",               rb_libddwaf_ddwaf_known_addresses, 1);
    rb_define_module_function(rb_mNative, "ddwaf_destroy",                       rb_libddwaf_ddwaf_destroy, 1);
    rb_define_module_function(rb_mNative, "ddwaf_context_init",                  rb_libddwaf_ddwaf_context_init, 1);
    rb_define_module_function(rb_mNative, "ddwaf_context_destroy",               rb_libddwaf_ddwaf_context_destroy, 1);
    rb_define_module_function(rb_mNative, "ddwaf_run",                           rb_libddwaf_ddwaf_run, 5);
}

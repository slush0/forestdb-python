from cpython.bytes cimport PyBytes_AsStringAndSize
from libc.stdint cimport uint8_t, uint16_t, uint32_t, uint64_t
from libc.stdlib cimport free
import sys

import sys
try:
    from os import fsencode
except ImportError:
    try:
        from sys import getfilesystemencoding as _getfsencoding
    except ImportError:
        _fsencoding = 'utf-8'
    else:
        _fsencoding = _getfsencoding()
    fsencode = lambda s: s.encode(_fsencoding)


cdef extern from "libforestdb/forestdb.h":
    ctypedef struct fdb_file_handle
    ctypedef struct fdb_kvs_handle
    ctypedef struct fdb_iterator
    ctypedef int fdb_status

    ctypedef void (*fdb_log_callback)(int err, const char **msg, void *ctx)

    ctypedef struct fdb_encryption_key:
        int algorithm
        uint8_t bytes[32]

    ctypedef struct fdb_config:
        uint16_t chunksize
        uint32_t blocksize
        uint64_t buffercache_size
        uint64_t wal_threshold
        bint wal_flush_before_commit
        bint auto_commit
        uint32_t purging_interval
        uint8_t seqtree_opt
        uint8_t durability_opt
        uint32_t flags
        uint32_t compaction_buf_maxsize
        bint cleanup_cache_onclose
        bint compress_document_body
        uint8_t compaction_mode
        uint8_t compaction_threshold
        uint64_t compaction_minimum_filesize
        uint64_t compaction_sleep_duration
        bint multi_kv_instances
        uint64_t prefetch_duration
        uint16_t num_wal_partitions
        uint16_t num_bcache_partitions
        void *compaction_cb
        uint32_t compaction_cb_mask
        void *compaction_cb_ctx
        size_t max_writer_lock_prob
        size_t num_compactor_threads
        size_t num_bgflusher_threads
        fdb_encryption_key encryption_key

    ctypedef struct fdb_kvs_config:
        bint create_if_missing
        void *custom_cmp

    ctypedef struct fdb_doc:
        size_t keylen
        size_t metalen
        size_t bodylen
        size_t size_ondisk
        void *key
        uint64_t seqnum
        uint64_t offset
        void *meta
        void *body
        bint deleted
        uint32_t flags

    ctypedef struct fdb_file_info:
        const char *filename
        const char *new_filename
        uint64_t doc_count
        uint64_t deleted_count
        uint64_t space_used
        uint64_t file_size
        size_t num_kv_stores

    ctypedef struct fdb_kvs_info:
        const char *name
        uint64_t last_seqnum
        uint64_t doc_count
        uint64_t deleted_count
        uint64_t space_used
        fdb_file_handle *file

    ctypedef struct fdb_kvs_ops_info:
        uint64_t num_sets
        uint64_t num_dels
        uint64_t num_commits
        uint64_t num_compacts
        uint64_t num_gets
        uint64_t num_iterator_gets
        uint64_t num_iterator_moves

    ctypedef struct fdb_kvs_name_list:
        size_t num_kvs_names
        char **kvs_names

    ctypedef struct fdb_iterator

    cdef fdb_status fdb_init(fdb_config *config)
    cdef fdb_config fdb_get_default_config()
    cdef fdb_kvs_config fdb_get_default_kvs_config()
    cdef fdb_status fdb_open(
        fdb_file_handle **ptr_fhandle,
        const char *filename,
        fdb_config *fconfig)
    cdef fdb_status fdb_set_log_callback(
        fdb_kvs_handle *handle,
        fdb_log_callback log_callback,
        void *ctx_data)

    cdef fdb_status fdb_kvs_open(
        fdb_file_handle *fhandle,
        fdb_kvs_handle **ptr_handle,
        const char *kvs_name,
        fdb_kvs_config *config)

    cdef fdb_status fdb_doc_create(
        fdb_doc **doc,
        const void *key,
        size_t keylen,
        const void *meta,
        size_t metalen,
        const void *body,
        size_t body_len)

    cdef fdb_status fdb_doc_update(
        fdb_doc **doc,
        const void *meta,
        size_t metalen,
        const void *body,
        size_t body_len),
    cdef void fdb_doc_set_sequnum(fdb_doc *doc, const uint64_t seqnum)
    cdef fdb_status fdb_doc_free(fdb_doc *doc)

    cdef fdb_status fdb_get(fdb_kvs_handle *handle, fdb_doc *doc)
    cdef fdb_status fdb_get_metaonly(fdb_kvs_handle *handle, fdb_doc *doc)
    cdef fdb_status fdb_get_byseq(fdb_kvs_handle *handle, fdb_doc *doc)
    cdef fdb_status fdb_get_metaonly_byseq(fdb_kvs_handle *hndl, fdb_doc *doc)
    cdef fdb_status fdb_get_byoffset(fdb_kvs_handle *hndl, fdb_doc *doc)

    cdef fdb_status fdb_set(fdb_kvs_handle *handle, fdb_doc *doc)
    cdef fdb_status fdb_del(fdb_kvs_handle *handle, fdb_doc *doc)

    cdef fdb_status fdb_get_kv(
        fdb_kvs_handle *handle,
        const void *key,
        size_t keylen,
        void **value_out,
        size_t *valuelen_out)
    cdef fdb_status fdb_set_kv(
        fdb_kvs_handle *handle,
        const void *key,
        size_t keylen,
        const void *value,
        size_t valuelen)
    cdef fdb_status fdb_del_kv(
        fdb_kvs_handle *handle,
        const void *key,
        size_t keylen)

    cdef fdb_status fdb_free_block(void *)

    cdef fdb_status fdb_commit(fdb_file_handle *fhandle, uint8_t opt)
    cdef fdb_status fdb_rollback(fdb_kvs_handle **handle, uint64_t seqnum)
    cdef fdb_status fdb_rollback_all(fdb_kvs_handle **handle, uint64_t marker)

    cdef fdb_status fdb_snapshot_open(
        fdb_kvs_handle *handle_in,
        fdb_kvs_handle **handle_out,
        uint64_t snapshot_seqnum)

    cdef fdb_status fdb_iterator_init(
        fdb_kvs_handle *handle,
        fdb_iterator **iterator,
        const void *min_key,
        size_t min_keylen,
        const void *max_key,
        size_t max_keylen,
        uint16_t options)
    cdef fdb_status fdb_iterator_sequence_init(
        fdb_kvs_handle *handle,
        fdb_iterator **iterator,
        const uint64_t min_seq,
        const uint64_t max_seq,
        uint16_t options)
    cdef fdb_status fdb_iterator_prev(fdb_iterator *iterator)
    cdef fdb_status fdb_iterator_next(fdb_iterator *iterator)
    cdef fdb_status fdb_iterator_get(fdb_iterator *iterator, fdb_doc **doc)
    cdef fdb_status fdb_iterator_get_metaonly(fdb_iterator *it, fdb_doc **doc)
    cdef fdb_status fdb_iterator_seek(
        fdb_iterator *iterator,
        const void *seek_key,
        const size_t seek_keylen,
        const uint8_t direction)
    cdef fdb_status fdb_iterator_seek_to_min(fdb_iterator *iterator)
    cdef fdb_status fdb_iterator_seek_to_max(fdb_iterator *iterator)
    cdef fdb_status fdb_iterator_close(fdb_iterator *iterator)

    cdef fdb_status fdb_compact(fdb_file_handle *handle, const char *filename)
    cdef fdb_status fdb_compact_with_cow(fdb_file_handle *h, const char *fn)
    cdef fdb_status fdb_cancel_compaction(fdb_file_handle *handle)
    cdef fdb_status fdb_rekey(fdb_file_handle *handle, fdb_encryption_key k)

    cdef size_t fdb_estimate_space_used(fdb_file_handle *handle)
    cdef fdb_status fdb_get_file_info(fdb_file_handle *h, fdb_file_info *i)
    cdef fdb_status fdb_get_kvs_info(fdb_file_handle *h, fdb_kvs_info *i)
    cdef fdb_status fdb_get_kvs_ops_info(fdb_file_handle *, fdb_kvs_ops_info *)

    cdef fdb_status fdb_get_kvs_seqnum(fdb_kvs_handle *, uint64_t *)
    cdef fdb_status fdb_get_kvs_name_list(fdb_file_handle *,
                                          fdb_kvs_name_list *)

    cdef fdb_status fdb_close(fdb_file_handle *)
    cdef fdb_status fdb_destroy(const char *, fdb_config *)
    cdef fdb_status fdb_shutdown()

    cdef fdb_status fdb_begin_transaction(fdb_file_handle *, uint8_t)
    cdef fdb_status fdb_end_transaction(fdb_file_handle *, uint8_t)
    cdef fdb_status fdb_abort_transaction(fdb_file_handle *)

    cdef fdb_status fdb_kvs_open(fdb_file_handle *,
                                 fdb_kvs_handle **,
                                 const char *name,
                                 fdb_kvs_config *)
    cdef fdb_status fdb_kvs_open_default(fdb_file_handle *,
                                         fdb_kvs_handle **,
                                         fdb_kvs_config **)

    cdef fdb_status fdb_kvs_close(fdb_kvs_handle *)
    cdef const char *fdb_error_msg(int err)


cdef uint32_t FDB_OPEN_FLAG_CREATE = 1
cdef uint32_t FDB_OPEN_FLAG_RDONLY = 2
cdef uint32_t FDB_OPEN_WITH_LEGACY_CRC = 4

cdef uint8_t FDB_COMMIT_NORMAL = 0x00
cdef uint8_t FDB_COMMIT_MANUAL_WAL_FLUSH = 0x01

cdef uint8_t FDB_SEQTREE_NOT_USE = 0
cdef uint8_t FDB_SEQTREE_USE = 1

cdef uint8_t FDB_DRB_NONE = 0x0
cdef uint8_t FDB_DRB_ODIRECT = 0x1
cdef uint8_t FDB_DRB_ASYNC = 0x2
cdef uint8_t FDB_DRB_ODIRECT_ASYNC = 0x3

cdef uint8_t FDB_COMPACTION_MANUAL = 0
cdef uint8_t FDB_COMPACTION_AUTO = 1

cdef uint8_t FDB_ISOLATION_READ_COMMITTED = 2
cdef uint8_t FDB_ISOLATION_READ_UNCOMMITTED = 3

cdef int FDB_ENCRYPTION_NONE = 0
cdef int FDB_ENCRYPTION_AES256 = 1

cdef uint16_t FDB_ITR_NONE = 0x00
cdef uint16_t FDB_ITR_NO_DELETES = 0x02
cdef uint16_t FDB_ITR_SKIP_MIN_KEY = 0x04
cdef uint16_t FDB_ITR_SKIP_MAX_KEY = 0x08

cdef uint8_t FDB_ITR_SEEK_HIGHER = 0x00
cdef uint8_t FDB_ITR_SEEK_LOWER = 0x01

cdef int FDB_RESULT_SUCCESS = 0
cdef int FDB_RESULT_INVALID_ARGS = -1
cdef int FDB_RESULT_OPEN_FAIL = 2
cdef int FDB_RESULT_NO_SUCH_FILE = -3
cdef int FDB_RESULT_WRITE_FAIL = -4
cdef int FDB_RESULT_READ_FAIL = -5
cdef int FDB_RESULT_CLOSE_FAIL = -6
cdef int FDB_RESULT_COMMIT_FAIL = -7
cdef int FDB_RESULT_KEY_NOT_FOUND = -9
cdef int FDB_RESULT_ITERATOR_FAIL = -12
cdef int FDB_RESULT_SEEK_FAIL = -13


# Helper method to ensure that a string-like object is converted to bytes.
cdef bytes encode(obj):
    if isinstance(obj, unicode):
        return obj.encode('utf-8')
    return bytes(obj)


cdef bint IS_PY3K = sys.version_info[0] == 3


EXC_MAPPING = {}
EXC_MESSAGES = {}


cdef inline _errcheck(int rc):
    if rc == 0:
        return

    exc_class = EXC_MAPPING.get(rc, Exception)
    exc_message = EXC_MESSAGES.get(rc, 'Unspecified error')
    raise exc_class('%s: %s' % (exc_message, rc))


cdef class ForestDB(object):
    cdef:
        bytes encoded_filename
        fdb_config config
        fdb_file_handle *handle
        readonly bint is_open
        readonly filename

    def __cinit__(self, filename, **config):
        cdef:
            fdb_status status

        self.filename = filename
        if isinstance(filename, unicode):
            self.encoded_filename = fsencode(filename)
        else:
            self.encoded_filename = bytes(filename)

        # Update configuration values.
        self.config = fdb_get_default_config()

        # Initialize and open database file handle.
        status = fdb_open(&self.handle, self.encoded_filename, &self.config)
        _errcheck(status)
        self.is_open = True

    def __dealloc__(self):
        if self.is_open and self.handle:
            fdb_close(self.handle)
            self.handle = <fdb_file_handle *>0

    cpdef bint close(self):
        if not self.is_open:
            return False

        try:
            _errcheck(fdb_close(self.handle))
        finally:
            self.handle = <fdb_file_handle *>0
        self.is_open = False
        return True


cdef class KVStore(object):
    cdef:
        bytes encoded_name
        fdb_kvs_config config
        fdb_kvs_handle *handle
        readonly bint is_open
        readonly ForestDB db
        readonly name

    def __cinit__(self, ForestDB db, name, **config):
        cdef:
            fdb_status status

        self.db = db
        if not db.is_open:
            raise Exception('Cannot create KVStore on closed database.')

        self.name = name
        self.encoded_name = encode(name)

        # Update configuration values.
        self.config = fdb_get_default_kvs_config()

        # Open key-value store.
        status = fdb_kvs_open(
            db.handle,
            &self.handle,
            <const char *>self.encoded_name,
            &self.config)
        _errcheck(status)
        self.is_open = True

    def __dealloc__(self):
        if self.is_open and self.db.handle:
            fdb_kvs_close(self.handle)

    cpdef bint close(self):
        if not self.is_open:
            return False

        try:
            _errcheck(fdb_kvs_close(self.handle))
        finally:
            self.handle = <fdb_kvs_handle *>0
        self.is_open = False
        return True

    cpdef bint set(self, key, value):
        cdef:
            char *kptr
            char *vptr
            int rc
            Py_ssize_t klen, vlen

        if IS_PY3K:
            key = encode(key)
            value = encode(value)

        PyBytes_AsStringAndSize(key, &kptr, &klen)
        PyBytes_AsStringAndSize(value, &vptr, &vlen)

        rc = fdb_set_kv(self.handle, <void *>kptr, <size_t>klen, <void *>vptr, <size_t>vlen)
        _errcheck(rc)

        return True

    cpdef bint delete(self, key):
        cdef:
            char *kptr
            Py_ssize_t klen

        if IS_PY3K:
            key = encode(key)

        PyBytes_AsStringAndSize(key, &kptr, &klen)
        _errcheck(fdb_del_kv(self.handle, <void *>kptr, <size_t>klen))
        return True

    cpdef get(self, key):
        cdef:
            char *kptr
            char *vptr
            int rc
            Py_ssize_t klen, vlen

        if IS_PY3K:
            key = encode(key)

        PyBytes_AsStringAndSize(key, &kptr, &klen)
        rc = fdb_get_kv(
            self.handle,
            <void *>kptr,
            <size_t>klen,
            <void **>(&vptr),
            <size_t *>(&vlen))
        if rc == 0:
            value = vptr[:vlen]
            free(vptr)
            if IS_PY3K:
                try:
                    return value.decode('utf-8')
                except UnicodeDecodeError:
                    pass
            return value

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
    cdef fdb_status fdb_get_kvs_info(fdb_kvs_handle *h, fdb_kvs_info *i)
    cdef fdb_status fdb_get_kvs_ops_info(fdb_kvs_handle *, fdb_kvs_ops_info *)

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
    cdef fdb_status fdb_kvs_remove(fdb_file_handle *, const char *)
    cdef const char *fdb_error_msg(int err)
    cdef size_t fdb_get_buffer_cache_used()


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
    elif obj is None:
        return obj
    return bytes(obj)

cdef decode(char *ptr, size_t n, free_ptr=True):
    value = ptr[:n]
    if free_ptr:
        free(ptr)
    if IS_PY3K:
        try:
            return value.decode('utf-8')
        except UnicodeDecodeError:
            pass
    return value

cdef bint IS_PY3K = sys.version_info[0] == 3

if IS_PY3K:
    long = int


class TransactionException(Exception):
    pass


EXC_MAPPING = {
    -9: KeyError,
    -26: TransactionException,
    -27: TransactionException,
}
EXC_MESSAGES = {
    -9: 'Key not found.',
    -26: 'Transaction failed.',
    -27: 'An active transaction in progress.',
}


cdef inline _errcheck(int rc):
    if rc == 0:
        return

    exc_class = EXC_MAPPING.get(rc, Exception)
    exc_message = EXC_MESSAGES.get(rc, 'Unspecified error')
    raise exc_class('%s: %s' % (exc_message, rc))


cdef class ForestDB(object):
    cdef:
        bint active_transaction
        bytes encoded_filename
        fdb_config config
        fdb_file_handle *handle
        public bint autocommit
        readonly bint is_open
        readonly filename

    def __cinit__(self, filename, autocommit=True, **config):
        cdef:
            fdb_status status

        self.filename = filename
        if isinstance(filename, unicode):
            self.encoded_filename = fsencode(filename)
        else:
            self.encoded_filename = encode(filename)

        # Set autocommit mode.
        self.autocommit = autocommit
        self.active_transaction = False

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

    cpdef bint open(self):
        if self.is_open:
            return False

        _errcheck(fdb_open(&self.handle, self.encoded_filename, &self.config))
        self.is_open = True
        return True

    cpdef bint close(self):
        if not self.is_open:
            return False

        try:
            _errcheck(fdb_close(self.handle))
        finally:
            self.handle = <fdb_file_handle *>0
        self.is_open = False
        return True

    def kv(self, name, **config):
        return KVStore(self, name, **config)

    def __getitem__(self, name):
        return KVStore(self, name)

    cpdef bint commit(self):
        if self.active_transaction:
            return False
        _errcheck(fdb_commit(self.handle, FDB_COMMIT_NORMAL))
        return True

    cpdef flush_wal(self):
        _errcheck(fdb_commit(self.handle, FDB_COMMIT_MANUAL_WAL_FLUSH))

    def buffer_cache_used(self):
        cdef size_t cache_used = fdb_get_buffer_cache_used()
        return cache_used

    def info(self):
        cdef:
            fdb_file_info info

        _errcheck(fdb_get_file_info(self.handle, &info))
        return {
            'filename': info.filename,
            'new_filename': info.new_filename,
            'doc_count': info.doc_count,
            'deleted_count': info.deleted_count,
            'space_used': info.space_used,
            'file_size': info.file_size,
            'num_kv_stores': info.num_kv_stores}

    cpdef bint begin_transaction(self, dirty_reads=False):
        if self.active_transaction:
            return False

        self.active_transaction = True
        if dirty_reads:
            isolation_level = FDB_ISOLATION_READ_UNCOMMITTED
        else:
            isolation_level = FDB_ISOLATION_READ_COMMITTED
        _errcheck(fdb_begin_transaction(self.handle, isolation_level))
        return True

    cpdef bint commit_transaction(self):
        if not self.active_transaction:
            return False
        _errcheck(fdb_end_transaction(self.handle, FDB_COMMIT_NORMAL))
        self.active_transaction = False
        return True

    cpdef bint rollback_transaction(self):
        if not self.active_transaction:
            return False
        _errcheck(fdb_abort_transaction(self.handle))
        self.active_transaction = False
        return True

    cpdef Transaction transaction(self):
        return Transaction.__new__(Transaction, self)


cdef class KVStore(object):
    cdef:
        bytes encoded_name
        fdb_file_handle *db_handle
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
        self.db_handle = self.db.handle

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

    cpdef bint open(self):
        if self.is_open and self.db.is_open and self.db_handle == self.db.handle:
            return False

        # Open key-value store.
        _errcheck(fdb_kvs_open(
            self.db.handle,
            &self.handle,
            <const char *>self.encoded_name,
            &self.config))
        self.is_open = True
        self.db_handle = self.db.handle
        return True

    cpdef bint close(self):
        if not self.is_open:
            return False

        try:
            _errcheck(fdb_kvs_close(self.handle))
        finally:
            self.handle = <fdb_kvs_handle *>0
        self.is_open = False
        return True

    cpdef drop(self):
        self.close()
        fdb_kvs_remove(self.db.handle, self.name)

    cpdef bint set(self, key, body):
        cdef:
            char *kptr
            char *bptr
            int rc
            Py_ssize_t klen, blen

        if IS_PY3K:
            key = encode(key)
            body = encode(body)

        PyBytes_AsStringAndSize(key, &kptr, &klen)
        PyBytes_AsStringAndSize(body, &bptr, &blen)

        _errcheck(fdb_set_kv(
            self.handle,
            <void *>kptr,
            <size_t>klen,
            <void *>bptr,
            <size_t>blen))

        if self.db.autocommit:
            self.db.commit()

        return True

    cpdef bint delete(self, key):
        cdef:
            char *kptr
            Py_ssize_t klen

        if IS_PY3K:
            key = encode(key)

        PyBytes_AsStringAndSize(key, &kptr, &klen)
        _errcheck(fdb_del_kv(self.handle, <void *>kptr, <size_t>klen))

        if self.db.autocommit:
            self.db.commit()

        return True

    cpdef get(self, key):
        cdef:
            char *kptr
            char *bptr
            int rc
            Py_ssize_t klen, blen

        if IS_PY3K:
            key = encode(key)

        PyBytes_AsStringAndSize(key, &kptr, &klen)
        rc = fdb_get_kv(
            self.handle,
            <void *>kptr,
            <size_t>klen,
            <void **>(&bptr),
            <size_t *>(&blen))
        if rc == 0:
            return decode(bptr, blen)

    cpdef get_by_seqnum(self, seqnum):
        cdef:
            Document document
            fdb_doc *doc

        _errcheck(fdb_doc_create(&doc, NULL, 0, NULL, 0, NULL, 0))
        doc.seqnum = seqnum
        _errcheck(fdb_get_byseq(self.handle, doc))
        document = Document.__new__(Document, self, _create=False)
        document.set_document(doc)
        return document

    def __setitem__(self, key, body):
        self.set(key, body)

    def __getitem__(self, key):
        if isinstance(key, slice):
            pass
        elif isinstance(key, (int, long)):
            result = self.get_by_seqnum(key)
        else:
            result = self.get(key)
        if result is None:
            raise KeyError(key)
        return result

    def __delitem__(self, key):
        if isinstance(key, slice):
            pass
        else:
            self.delete(key)

    def document(self, key=None, meta=None, body=None, seqnum=None,
                 _create=True):
        return Document.__new__(Document, self, key, meta, body, seqnum,
                                _create)

    cpdef last_seqnum(self):
        cdef uint64_t seqnum
        _errcheck(fdb_get_kvs_seqnum(self.handle, &seqnum))
        return seqnum

    def info(self):
        cdef:
            fdb_kvs_info info

        _errcheck(fdb_get_kvs_info(self.handle, &info))
        return {
            'name': info.name,
            'last_seqnum': info.last_seqnum,
            'doc_count': info.doc_count,
            'deleted_count': info.deleted_count,
            'space_used': info.space_used}

    def ops_info(self):
        cdef:
            fdb_kvs_ops_info info

        _errcheck(fdb_get_kvs_ops_info(self.handle, &info))
        return {
            'num_sets': info.num_sets,
            'num_dels': info.num_dels,
            'num_commits': info.num_commits,
            'num_compacts': info.num_compacts,
            'num_gets': info.num_gets,
            'num_iterator_gets': info.num_iterator_gets,
            'num_iterator_moves': info.num_iterator_moves}

    cpdef Cursor cursor(self, start=None, stop=None, skip_start=False,
                        skip_stop=False, reverse=False):
        return Cursor(
            self,
            start=start,
            stop=stop,
            skip_start=skip_start,
            skip_stop=skip_stop,
            reverse=reverse)

    def __iter__(self):
        return iter(self.cursor())


cdef class Document(object):
    cdef:
        fdb_doc *handle
        readonly KVStore kv

    def __cinit__(self, KVStore kv, key=None, meta=None, body=None,
                  seqnum=None, _create=True):
        cdef:
            bytes bkey, bmeta, bbody
            char *_key = NULL
            char *_meta = NULL
            char *_body = NULL
            Py_ssize_t _key_len = 0, _meta_len = 0, _body_len = 0
            fdb_status status

        self.kv = kv

        if _create:
            bkey = encode(key)
            bmeta = encode(meta)
            bbody = encode(body)

            if key is not None:
                PyBytes_AsStringAndSize(bkey, &_key, &_key_len)
            if meta is not None:
                PyBytes_AsStringAndSize(bmeta, &_meta, &_meta_len)
            if body is not None:
                PyBytes_AsStringAndSize(bbody, &_body, &_body_len)

            _errcheck(fdb_doc_create(
                &self.handle,
                <void *>(_key),
                <size_t>(_key_len),
                <void *>(_meta),
                <size_t>(_meta_len),
                <void *>(_body),
                <size_t>(_body_len)))

            if seqnum is not None:
                self.handle.seqnum = <uint64_t>seqnum

    def __dealloc__(self):
        if self.handle:
            fdb_doc_free(self.handle)

    def close(self):
        if self.handle:
            fdb_doc_free(self.handle)
            self.handle = NULL
            return True
        else:
            return False

    cdef _check_handle(self):
        if not self.handle:
            raise ValueError('Document handle not initialized.')

    cdef set_document(self, fdb_doc *doc):
        self.handle = doc

    cpdef update(self, meta, body):
        cdef:
            char *_meta = NULL
            char *_body = NULL
            Py_ssize_t _meta_len = 0, _body_len = 0

        if IS_PY3K:
            meta = encode(meta)
            body = encode(body)

        if meta is not None:
            PyBytes_AsStringAndSize(meta, &_meta, &_meta_len)
        if body is not None:
            PyBytes_AsStringAndSize(body, &_body, &_body_len)

        _errcheck(fdb_doc_update(
            &(self.handle),
            <void *>(_meta),
            <size_t>(_meta_len),
            <void *>(_body),
            <size_t>(_body_len)))

    cpdef insert(self):
        _errcheck(fdb_set(self.kv.handle, self.handle))
        if self.kv.db.autocommit:
            self.kv.db.commit()
        return self.handle.seqnum

    cpdef get(self):
        _errcheck(fdb_get(self.kv.handle, self.handle))
        return self.handle.seqnum

    cpdef get_by_seqnum(self):
        _errcheck(fdb_get_byseq(self.kv.handle, self.handle))
        return self.handle.seqnum

    cpdef get_metadata(self):
        _errcheck(fdb_get_metaonly(self.kv.handle, self.handle))
        return self.handle.seqnum

    cpdef get_metadata_by_seqnum(self):
        _errcheck(fdb_get_metaonly_byseq(self.kv.handle, self.handle))
        return self.handle.seqnum

    cpdef delete(self):
        _errcheck(fdb_del(self.kv.handle, self.handle))
        if self.kv.db.autocommit:
            self.kv.db.commit()

    property key:
        def __get__(self):
            self._check_handle()
            return decode(<char *>self.handle.key, self.handle.keylen, False)

    property meta:
        def __get__(self):
            self._check_handle()
            return decode(<char *>self.handle.meta, self.handle.metalen, False)

        def __set__(self, value):
            self._check_handle()
            self.update(value, self.body)

    property body:
        def __get__(self):
            self._check_handle()
            return decode(<char *>self.handle.body, self.handle.bodylen, False)

        def __set__(self, value):
            self._check_handle()
            self.update(self.meta, value)

    property seqnum:
        def __get__(self):
            self._check_handle()
            return self.handle.seqnum

        def __set__(self, value):
            self._check_handle()
            self.handle.seqnum = <uint64_t>(value)

    property disk_offset:
        def __get__(self):
            self._check_handle()
            return self.handle.offset


cdef class Cursor(object):
    cdef:
        bint reverse, stopped
        bytes bstart, bstop
        KVStore kv
        fdb_iterator *handle
        uint16_t options

    def __cinit__(self, KVStore kv, start=None, stop=None, skip_start=False,
                  skip_stop=False, reverse=False):
        self.kv = kv
        self.bstart = encode(start)
        self.bstop = encode(stop)
        self.reverse = reverse
        self.options = FDB_ITR_NO_DELETES
        if skip_start:
            self.options |= FDB_ITR_SKIP_MIN_KEY
        if skip_stop:
            self.options |= FDB_ITR_SKIP_MAX_KEY

        self.handle = NULL
        self.stopped = True

    def __dealloc__(self):
        if self.handle and self.kv.is_open and self.kv.db.is_open:
            fdb_iterator_close(self.handle)

    def __iter__(self):
        cdef:
            char *_start = NULL
            char *_stop = NULL
            Py_ssize_t start_len = 0, stop_len = 0

        self.stopped = False
        if self.bstart is not None:
            PyBytes_AsStringAndSize(self.bstart, &_start, &start_len)
        if self.bstop is not None:
            PyBytes_AsStringAndSize(self.bstop, &_stop, &stop_len)

        _errcheck(fdb_iterator_init(
            self.kv.handle,
            &self.handle,
            <void *>_start,
            start_len,
            <void *>_stop,
            stop_len,
            self.options))

        if self.reverse:
            fdb_iterator_seek_to_max(self.handle)

        return self

    def __next__(self):
        cdef:
            fdb_doc *doc = NULL
            fdb_status status

        if self.stopped:
            raise StopIteration

        status = fdb_iterator_get(self.handle, &doc)
        if status != FDB_RESULT_SUCCESS:
            raise StopIteration

        obj = self._value_from_doc(doc)
        if self.reverse:
            status = fdb_iterator_prev(self.handle)
        else:
            status = fdb_iterator_next(self.handle)

        if status == FDB_RESULT_ITERATOR_FAIL:
            self.stopped = True

        return obj

    cdef _value_from_doc(self, fdb_doc *doc):
        cdef Document document
        document = Document.__new__(Document, self.kv, _create=False)
        document.set_document(doc)
        return document

    cpdef seek(self, key, mode=FDB_ITR_SEEK_HIGHER):
        cdef:
            bytes bkey = encode(key)
            char *_key
            Py_ssize_t keylen

        PyBytes_AsStringAndSize(bkey, &_key, &keylen)
        _errcheck(fdb_iterator_seek(self.handle, _key, keylen, mode))

    cpdef first(self):
        _errcheck(fdb_iterator_seek_to_min(self.handle))

    cpdef last(self):
        _errcheck(fdb_iterator_seek_to_max(self.handle))


cdef class Transaction(object):
    cdef:
        ForestDB db

    def __cinit__(self, ForestDB db):
        self.db = db

    cpdef begin(self):
        self.db.begin_transaction()

    def __enter__(self):
        self.begin()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type:
            self.rollback(False)
        else:
            try:
                self.commit(False)
            except:
                self.rollback(False)
                raise

    cpdef commit(self, begin=True):
        self.db.commit_transaction()
        if begin:
            self.begin()

    cpdef rollback(self, begin=True):
        self.db.rollback_transaction()
        if begin:
            self.begin()

## forestdb-python

Fast Python bindings for [forestdb](https://github.com/couchbase/forestdb/), an embedded key-value storage engine developed by Couchbase. The main index structure is built from [Hierarchical B+-Tree based Trie](http://db.csail.mit.edu/sigmod11contest/sigmod_2011_contest_poster_jungsang_ahn.pdf) (pdf).

> Compared with traditional B+-Tree based storage engines, ForestDB shows significantly better read and write performance with less storage overhead.

### ForestDB Features

* Keys, values and metadata are treated as arbitrary binary data.
* Values can be retrieved by key or by a unique integer *sequence number*.
* Write-Ahead-Logging (WAL) and its in-memory index are used to reduce the main index lookup/update overhead.
* Multi-Version Concurrency Control (MVCC) support and append-only storage layer.
* Multiple snapshots can be created from a given ForestDB instance to provide different views of database over time.
* Rollback is supported to revert the database to a point-in-time.
* Ranged iteration by keys is supported for partial or full range lookup operation (cursors).
* Transactional support with read committed or read uncommitted isolation.
* Encryption (AES256)

### Python Binding Features

* Written in Cython to give best performance.
* Support for virtually all public APIs.

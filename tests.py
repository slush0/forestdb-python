import os
import sys
import unittest

from forestdb import ForestDB
from forestdb import TransactionException


DB_FILE = 'forest-test.db'


class BaseTestCase(unittest.TestCase):
    def setUp(self):
        if os.path.exists(DB_FILE):
            os.unlink(DB_FILE)

        self.db = self.get_db()
        self.kv = self.db['kv-1']

    def tearDown(self):
        self.db.close()
        if os.path.exists(DB_FILE):
            os.unlink(DB_FILE)

    def get_db(self):
        return ForestDB(DB_FILE)


class TestForestDB(BaseTestCase):
    def test_db_open_close(self):
        self.kv['k1'] = 'v1'

        kv2 = self.db['kv2']
        kv2['k1'] = 'v2'

        self.kv.close()
        kv2.close()
        self.db.close()

        self.db.open()
        self.kv.open()
        kv2.open()

        self.assertEqual(self.kv['k1'], 'v1')
        self.assertEqual(kv2['k1'], 'v2')

    def test_autocommit_off(self):
        self.kv['k1'] = 'v1'

        self.kv.close()
        self.db.close()

        self.db.autocommit = False

        self.db.open()
        self.kv.open()

        self.assertEqual(self.kv['k1'], 'v1')
        self.kv['k1'] = 'v1-e'
        self.kv['k2'] = 'v2'
        self.kv.close()
        self.db.close()

        self.db.open()
        self.kv.open()
        self.assertEqual(self.kv['k1'], 'v1')
        self.assertRaises(KeyError, lambda: self.kv['k2'])

    def test_kvs_names(self):
        self.assertEqual(self.db.get_kv_names(), ['default', 'kv-1'])

        self.db.kv('kv-2')
        self.db.kv('kv-3')
        self.assertEqual(self.db.get_kv_names(), 
                         ['default', 'kv-1', 'kv-2', 'kv-3'])


class TestDBEncryption(BaseTestCase):
    def get_db(self):
        return ForestDB(DB_FILE, encryption_key='testing')

    def test_encryption(self):
        val = 'value-testing-encryption'
        self.kv['k1'] = val
        self.assertEqual(self.kv['k1'], val)

        self.kv.close()
        self.db.close()

        self.db.open()
        self.kv.open()
        self.assertEqual(self.kv['k1'], val)

        self.db.close()

        with open(DB_FILE, 'rb') as fh:
            data = fh.read()
            self.assertFalse(val in data)


class TestDBInfo(BaseTestCase):
    def setUp(self):
        super(TestDBInfo, self).setUp()
        self.kv2 = self.db.kv('kv2')

        self.kv.update(k1='v1', k2='v2', k3='v3', k4='v4')
        del self.kv['k4']

        self.kv2.update(k1='v1-2', k2='v2-2')

    def test_db_info(self):
        info = self.db.info()
        self.assertEqual(info['num_kv_stores'], 3)
        self.assertEqual(info['doc_count'], 5)
        self.assertEqual(info['deleted_count'], 1)

    def test_kv_info(self):
        info = self.kv.info()
        self.assertEqual(info['deleted_count'], 1)
        self.assertEqual(info['doc_count'], 3)
        self.assertEqual(info['last_seqnum'], 5)

        info = self.kv2.info()
        self.assertEqual(info['deleted_count'], 0)
        self.assertEqual(info['doc_count'], 2)
        self.assertEqual(info['last_seqnum'], 2)

    def test_kv_ops_info(self):
        info = self.kv.ops_info()
        self.assertEqual(info['num_sets'], 4)
        self.assertEqual(info['num_dels'], 1)
        self.assertEqual(info['num_commits'], 3)
        self.assertEqual(info['num_gets'], 0)

        info = self.kv2.ops_info()
        self.assertEqual(info['num_sets'], 2)
        self.assertEqual(info['num_dels'], 0)
        self.assertEqual(info['num_commits'], 3)
        self.assertEqual(info['num_gets'], 0)

        self.kv2['k1']
        try:
            self.kv2['kx']
        except KeyError:
            pass

        info = self.kv2.ops_info()
        self.assertEqual(info['num_sets'], 2)
        self.assertEqual(info['num_dels'], 0)
        self.assertEqual(info['num_commits'], 3)
        self.assertEqual(info['num_gets'], 2)


class TestKVOperations(BaseTestCase):
    def test_get_set_del(self):
        self.kv.set('k1', 'v1')
        self.kv.set('k2', 'v2')
        self.assertEqual(self.kv.get('k1'), 'v1')
        self.assertEqual(self.kv.get('k2'), 'v2')
        self.assertIsNone(self.kv.get('k3'))

        self.kv.delete('k1')
        self.assertIsNone(self.kv.get('k1'))

        # Can delete non-existant keys.
        self.kv.delete('k3')

    def test_dict_api(self):
        self.kv['k1'] = 'v1'
        self.kv['k2'] = 'v2'
        self.assertEqual(self.kv['k1'], 'v1')
        self.assertEqual(self.kv['k2'], 'v2')
        self.assertRaises(KeyError, lambda: self.kv['k3'])

        del self.kv['k1']
        self.assertRaises(KeyError, lambda: self.kv['k1'])

        # Can delete non-existant keys.
        del self.kv['k3']

    def test_update(self):
        self.kv.update(k1='v1', k2='v2', k3='v3')
        self.assertEqual(self.kv['k1'], 'v1')
        self.assertEqual(self.kv['k2'], 'v2')
        self.assertEqual(self.kv['k3'], 'v3')

    def test_empty_values(self):
        self.kv['k1'] = ''
        self.assertEqual(self.kv['k1'], '')

    def test_seqnum(self):
        self.kv['k1'] = 'v1'
        self.kv['k2'] = 'v2'

        seq = self.kv.last_seqnum()
        body = self.kv.get_by_seqnum(seq)
        self.assertEqual(body, 'v2')

        body = self.kv.get_by_seqnum(seq - 1)
        self.assertEqual(body, 'v1')

    def assertSlice(self, range_iter, expected):
        self.assertEqual([result for result in range_iter], expected)

    def test_get_range(self):
        self.kv.update(aa='r1', bb='r2', bbb='r3', dd='r4', ee='r5', gg='r6')
        self.assertSlice(self.kv['bb':'ee'], [
            ('bb', 'r2'),
            ('bbb', 'r3'),
            ('dd', 'r4'),
            ('ee', 'r5'),
        ])
        self.assertSlice(self.kv['cc':'ff'], [
            ('dd', 'r4'),
            ('ee', 'r5'),
        ])

        self.assertSlice(self.kv[:'cc'], [
            ('aa', 'r1'),
            ('bb', 'r2'),
            ('bbb', 'r3'),
        ])
        self.assertSlice(self.kv['cc':], [
            ('dd', 'r4'),
            ('ee', 'r5'),
            ('gg', 'r6'),
        ])
        self.assertSlice(self.kv[:], [
            ('aa', 'r1'),
            ('bb', 'r2'),
            ('bbb', 'r3'),
            ('dd', 'r4'),
            ('ee', 'r5'),
            ('gg', 'r6'),
        ])

        self.assertSlice(self.kv['cc1':'cc2'], [])
        self.assertSlice(self.kv[:'\x01'], [])
        self.assertSlice(self.kv['\xff':], [])

    def test_get_range_reverse(self):
        self.kv.update(aa='r1', bb='r2', bbb='r3', dd='r4', ee='r5', gg='r6')

        # Reverse is implied.
        self.assertSlice(self.kv['ee':'bb'], [
            ('ee', 'r5'),
            ('dd', 'r4'),
            ('bbb', 'r3'),
            ('bb', 'r2'),
        ])
        self.assertSlice(self.kv['bb':'ee':True], [
            ('ee', 'r5'),
            ('dd', 'r4'),
            ('bbb', 'r3'),
            ('bb', 'r2'),
        ])
        self.assertSlice(self.kv['ff':'cc'], [
            ('ee', 'r5'),
            ('dd', 'r4'),
        ])

        self.assertSlice(self.kv[:'cc':True], [
            ('bbb', 'r3'),
            ('bb', 'r2'),
            ('aa', 'r1'),
        ])
        self.assertSlice(self.kv['cc'::True], [
            ('gg', 'r6'),
            ('ee', 'r5'),
            ('dd', 'r4'),
        ])
        self.assertSlice(self.kv[::True], [
            ('gg', 'r6'),
            ('ee', 'r5'),
            ('dd', 'r4'),
            ('bbb', 'r3'),
            ('bb', 'r2'),
            ('aa', 'r1'),
        ])

        self.assertSlice(self.kv['cc2':'cc1'], [])
        self.assertSlice(self.kv[:'\x01':True], [])
        self.assertSlice(self.kv['\xff'::True], [])

    def keys_values_iterators(self):
        K = self.kv
        K.update(aa='r1', bb='r2', dd='r3', ee='r4')

        self.assertEqual(list(K.keys()), ['aa', 'bb', 'dd', 'ee'])
        self.assertEqual(list(K.keys(reverse=True)), 
                         ['ee', 'dd', 'bb', 'aa'])
        self.assertEqual(list(K.keys(start='aa2')), ['bb', 'dd', 'ee'])
        self.assertEqual(list(K.keys(start='cc', reverse=True)), 
                         ['bb', 'aa'])
        self.assertEqual(list(K.keys(start='\xff')), [])

        self.assertEqual(list(K.values()), ['r1', 'r2', 'r3', 'r4'])
        self.assertEqual(list(K.values(reverse=True)), 
                         ['r4', 'r3', 'r2', 'r1'])
        self.assertEqual(list(K.values(start='aa2')), ['r2', 'r3', 'r4'])
        self.assertEqual(list(K.values(start='cc', reverse=True)), 
                         ['r2', 'r1'])
        self.assertEqual(list(K.keys(start='\x01', reverse=True)), [])

    def test_delete_range(self):
        for i in range(1, 10):
            self.kv['k%s' % i] = 'v%s' % i

        del self.kv['k2':'k55']
        self.assertEqual([key for key in self.kv.keys()], [
            'k1', 'k6', 'k7', 'k8', 'k9'])
        

class TestDocument(BaseTestCase):
    def test_document_properties(self):
        doc1 = self.kv.document('k1', 'm1', 'v1')
        doc2 = self.kv.document('k2')
        doc3 = self.kv.document(_create=False)

        self.assertEqual(doc1.key, 'k1')
        self.assertEqual(doc1.meta, 'm1')
        self.assertEqual(doc1.body, 'v1')

        self.assertEqual(doc2.key, 'k2')
        self.assertEqual(doc2.meta, '')
        self.assertEqual(doc2.body, '')

        self.assertRaises(ValueError, lambda: doc3.key)
        self.assertRaises(ValueError, lambda: doc3.meta)
        self.assertRaises(ValueError, lambda: doc3.body)

    def test_document_get_set_del(self):
        doc1 = self.kv.document('k1', 'm1', 'v1')
        doc2 = self.kv.document('k2', 'm2', 'v2')
        doc1.insert()
        doc2.insert()

        # Seqnum is populated.
        self.assertEqual(doc1.seqnum, 1)
        self.assertEqual(doc2.seqnum, 2)

        # Data is stored.
        self.assertEqual(self.kv['k1'], 'v1')
        self.assertEqual(self.kv['k2'], 'v2')

        # Empty doc created with key initialized.
        doc1_db = self.kv.document('k1')
        self.assertEqual(doc1_db.meta, '')
        self.assertEqual(doc1_db.body, '')

        # Retrieve from db, fields are populated.
        doc1_db.get()
        self.assertEqual(doc1_db.seqnum, 1)
        self.assertEqual(doc1_db.meta, 'm1')
        self.assertEqual(doc1_db.body, 'v1')

        # Retrieve only metadata.
        doc2_db = self.kv.document('k2')
        doc2_db.get_metadata()
        self.assertEqual(doc2_db.seqnum, 2)
        self.assertEqual(doc2_db.meta, 'm2')

        # Can load by seqnum.
        doc1_seq = self.kv.document(seqnum=1)
        doc1_seq.get_by_seqnum()
        self.assertEqual(doc1_seq.seqnum, 1)
        self.assertEqual(doc1_seq.key, 'k1')
        self.assertEqual(doc1_seq.meta, 'm1')
        self.assertEqual(doc1_seq.body, 'v1')

        # Can load metadata by seqnum.
        doc2_seq = self.kv.document(seqnum=2)
        doc2_seq.get_metadata_by_seqnum()
        self.assertEqual(doc2_seq.seqnum, 2)
        self.assertEqual(doc2_seq.key, 'k2')
        self.assertEqual(doc2_seq.meta, 'm2')

        # Delete works.
        doc1_db.delete()
        self.assertRaises(KeyError, lambda: self.kv['k1'])

    def test_missing_docs(self):
        # Attempt to get missing key.
        d = self.kv.document('k1')
        self.assertRaises(KeyError, d.get)

        # Attempt to get missing seqnum.
        d = self.kv.document(seqnum=10)
        self.assertRaises(KeyError, d.get_by_seqnum)

    def test_insert_missing(self):
        d = self.kv.document()
        self.assertRaises(Exception, d.insert)


class TestTransaction(BaseTestCase):
    def test_transaction(self):
        with self.db.transaction():
            self.kv['k1'] = 'v1'
            self.kv['k2'] = 'v2'
            self.kv['k3'] = 'v3'

        self.assertEqual(self.kv['k1'], 'v1')
        self.assertEqual(self.kv['k2'], 'v2')

        with self.db.transaction() as txn:
            self.kv['k1'] = 'v1-e'
            self.kv['k2'] = 'v2-e'

        self.assertEqual(self.kv['k1'], 'v1-e')
        self.assertEqual(self.kv['k2'], 'v2-e')

        with self.db.transaction() as txn:
            del self.kv['k2']
            self.assertRaises(KeyError, lambda: self.kv['k2'])

        self.assertRaises(KeyError, lambda: self.kv['k2'])

    def test_rollback(self):
        self.kv['k1'] = 'v1'
        self.kv['k2'] = 'v2'
        self.kv['k3'] = 'v3'

        with self.db.transaction() as txn:
            self.kv['k1'] = 'v1-e'
            self.kv['k2'] = 'v2-e'
            del self.kv['k3']
            txn.rollback()

        self.assertEqual(self.kv['k1'], 'v1')
        self.assertEqual(self.kv['k2'], 'v2')
        self.assertEqual(self.kv['k3'], 'v3')

    def test_commit_rollback(self):
        with self.db.transaction() as txn:
            self.kv['k1'] = 'v1'
            self.kv['k2'] = 'v2'
            txn.commit()
            self.kv['k2'] = 'v2-e'
            txn.rollback()

        self.assertEqual(self.kv['k1'], 'v1')
        self.assertEqual(self.kv['k2'], 'v2')

        with self.db.transaction() as txn:
            self.kv['k1'] = 'v1-e'
            self.kv['k2'] = 'v2-e'
            txn.rollback()
            self.kv['k1'] = 'v1-e2'

        self.assertEqual(self.kv['k1'], 'v1-e2')
        self.assertEqual(self.kv['k2'], 'v2')


class TestCursor(BaseTestCase):
    def setUp(self):
        super(TestCursor, self).setUp()

        self.test_data = [
            ('aa', 'r1'),
            ('bb', 'r2'),
            ('bbb', 'r3'),
            ('dd', 'r4'),
            ('ee', 'r5'),
            ('gg', 'r6'),
            ('zz', 'r7'),
        ]
        for key, value in self.test_data:
            self.kv[key] = value

    def test_simple_iteration(self):
        documents = [row for row in self.kv]
        data = [(doc.key, doc.body) for doc in documents]
        self.assertEqual(self.test_data, data)

    def test_multi_iterations(self):
        cursor = self.kv.cursor()

        data = [(doc.key, doc.body) for doc in cursor]
        self.assertEqual(self.test_data, data)

        data = [(doc.key, doc.body) for doc in cursor]
        self.assertEqual(self.test_data, data)

    def assertRange(self, cursor, expected):
        data = [(doc.key, doc.body) for doc in cursor]
        self.assertEqual(data, expected)

    def test_cursor_range_start(self):
        cursor = self.kv.cursor(start='dd')  # Key exists.
        self.assertRange(cursor, [
            ('dd', 'r4'),
            ('ee', 'r5'),
            ('gg', 'r6'),
            ('zz', 'r7')])

        cursor = self.kv.cursor(start='dd', skip_start=True)
        self.assertRange(cursor, [
            ('ee', 'r5'),
            ('gg', 'r6'),
            ('zz', 'r7')])

        cursor = self.kv.cursor(start='de')  # Key does not exist.
        self.assertRange(cursor, [
            ('ee', 'r5'),
            ('gg', 'r6'),
            ('zz', 'r7')])

        cursor = self.kv.cursor(start='de', skip_start=True)
        self.assertRange(cursor, [
            ('ee', 'r5'),  # No effect since not exact match.
            ('gg', 'r6'),
            ('zz', 'r7')])

        cursor = self.kv.cursor(start='\x01')  # Key below first record.
        self.assertRange(cursor, self.test_data)

        cursor = self.kv.cursor(start='\x01', skip_start=True)
        self.assertRange(cursor, self.test_data)

        cursor = self.kv.cursor(start='\xff')  # Key after last record.
        self.assertRange(cursor, [])

    def test_cursor_range_stop(self):
        cursor = self.kv.cursor(stop='dd')  # Key exists.
        self.assertRange(cursor, [
            ('aa', 'r1'),
            ('bb', 'r2'),
            ('bbb', 'r3'),
            ('dd', 'r4')])

        cursor = self.kv.cursor(stop='dd', skip_stop=True)
        self.assertRange(cursor, [
            ('aa', 'r1'),
            ('bb', 'r2'),
            ('bbb', 'r3')])

        cursor = self.kv.cursor(stop='cc')  # Key does not exist.
        self.assertRange(cursor, [
            ('aa', 'r1'),
            ('bb', 'r2'),
            ('bbb', 'r3')])

        cursor = self.kv.cursor(stop='cc', skip_stop=True)
        self.assertRange(cursor, [
            ('aa', 'r1'),
            ('bb', 'r2'),
            ('bbb', 'r3')])

        cursor = self.kv.cursor(stop='\x01')  # Key below first record.
        self.assertRange(cursor, [])

        cursor = self.kv.cursor(stop='\xff')  # Key after last record.
        self.assertRange(cursor, self.test_data)

        cursor = self.kv.cursor(stop='\xff', skip_stop=True)
        self.assertRange(cursor, self.test_data)

    def test_start_stop(self):
        cursor = self.kv.cursor(start='bb', stop='ee')  # Both exist.
        self.assertRange(cursor, [
            ('bb', 'r2'),
            ('bbb', 'r3'),
            ('dd', 'r4'),
            ('ee', 'r5')])

        cursor = self.kv.cursor(start='cc', stop='ff')  # Neither exist.
        self.assertRange(cursor, [
            ('dd', 'r4'),
            ('ee', 'r5')])

        cursor = self.kv.cursor(start='\x01', stop='\x02')  # Below.
        self.assertRange(cursor, [])

        cursor = self.kv.cursor(start='\xfe', stop='\xff')  # Above.
        self.assertRange(cursor, [])

        cursor = self.kv.cursor(start='aa', stop='aa') # Same, exists.
        self.assertRange(cursor, [('aa', 'r1')])

        cursor = self.kv.cursor(start='cc', stop='cc') # Same, not exists.
        self.assertRange(cursor, [])

    def test_skip_start_stop(self):
        cursor = self.kv.cursor('dd', 'gg', True, True)  # Both exist.
        self.assertRange(cursor, [('ee', 'r5')])

        cursor = self.kv.cursor('dc', 'fg', True, True)  # Neither exist.
        self.assertRange(cursor, [('dd', 'r4'), ('ee', 'r5')])

        cursor = self.kv.cursor(start='aa', stop='aa', skip_start=True)
        self.assertRange(cursor, [])
        cursor = self.kv.cursor(start='aa', stop='aa', skip_stop=True)
        self.assertRange(cursor, [])

    def test_start_gt_stop(self):
        cursor = self.kv.cursor(start='dd', stop='aa')
        self.assertRange(cursor, [])

    def test_reverse(self):
        cursor = self.kv.cursor(start='aa', stop='dd', reverse=True)
        self.assertRange(cursor, [
            ('dd', 'r4'),
            ('bbb', 'r3'),
            ('bb', 'r2'),
            ('aa', 'r1')])

        cursor = self.kv.cursor(start='bc', stop='kk', reverse=True)
        self.assertRange(cursor, [
            ('gg', 'r6'),
            ('ee', 'r5'),
            ('dd', 'r4')])

        cursor = self.kv.cursor(start='cc', reverse=True)
        self.assertRange(cursor, [
            ('zz', 'r7'),
            ('gg', 'r6'),
            ('ee', 'r5'),
            ('dd', 'r4')])

        cursor = self.kv.cursor(stop='cc', reverse=True)
        self.assertRange(cursor, [
            ('bbb', 'r3'),
            ('bb', 'r2'),
            ('aa', 'r1')])

        cursor = self.kv.cursor(reverse=True)
        self.assertRange(cursor, list(reversed(self.test_data)))


class TestSnapshots(BaseTestCase):
    def test_snapshot(self):
        self.kv.update(k1='v1', k2='v2', k3='v3')

        snap = self.kv.snapshot()
        self.assertEqual(snap['k1'], 'v1')
        self.assertEqual(snap['k2'], 'v2')
        self.assertEqual(snap['k3'], 'v3')

        self.kv['k1'] = 'v1-e'
        self.kv['k2'] = 'v2-e'
        del self.kv['k3']

        self.assertEqual(snap['k1'], 'v1')
        self.assertEqual(snap['k2'], 'v2')
        self.assertEqual(snap['k3'], 'v3')

        self.assertEqual(self.kv['k1'], 'v1-e')
        self.assertEqual(self.kv['k2'], 'v2-e')
        self.assertFalse('k3' in self.kv)

        snap2 = self.kv.snapshot()

        self.kv['k1'] = 'v1-e2'
        self.kv['k3'] = 'v3-e2'

        self.assertEqual(snap['k1'], 'v1')
        self.assertEqual(snap['k2'], 'v2')
        self.assertEqual(snap['k3'], 'v3')
        self.assertEqual(snap2['k1'], 'v1-e')
        self.assertEqual(snap2['k2'], 'v2-e')
        self.assertFalse('k3' in snap2)

        self.assertEqual(self.kv['k1'], 'v1-e2')
        self.assertEqual(self.kv['k2'], 'v2-e')
        self.assertEqual(self.kv['k3'], 'v3-e2')

        self.assertEqual([doc.body for doc in snap], ['v1', 'v2', 'v3'])
        self.assertEqual([doc.body for doc in snap2], ['v1-e', 'v2-e'])


if __name__ == '__main__':
    unittest.main(argv=sys.argv)

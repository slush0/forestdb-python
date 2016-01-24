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

        self.db = ForestDB(DB_FILE)
        self.kv = self.db['kv-1']

    def tearDown(self):
        self.db.close()
        if os.path.exists(DB_FILE):
            os.unlink(DB_FILE)


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

    def test_empty_values(self):
        self.kv['k1'] = ''
        self.assertEqual(self.kv['k1'], '')

    def test_seqnum(self):
        self.kv['k1'] = 'v1'
        self.kv['k2'] = 'v2'
        seq = self.kv.last_seqnum()
        doc = self.kv.get_by_seqnum(seq)
        self.assertEqual(doc.key, 'k2')
        self.assertEqual(doc.meta, '')
        self.assertEqual(doc.body, 'v2')
        self.assertEqual(doc.seqnum, 2)


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


if __name__ == '__main__':
    unittest.main(argv=sys.argv)

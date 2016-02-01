from distutils.core import setup, Extension

try:
    from Cython.Build import cythonize
except ImportError:
    raise RuntimeError('Cython must be installed to build unqlite-python.')


python_source = 'forestdb.pyx'

extension = Extension(
    'forestdb',
    sources=[python_source],
    libraries=['forestdb'])

setup(
    name='forestdb',
    version='0.1.1',
    description='Fast Python bindings for the forestdb embedded database.',
    author='Charles Leifer',
    author_email='',
    url='https://github.com/coleifer/forestdb-python',
    license='MIT',
    install_requires=['cython'],
    ext_modules=cythonize(extension)
)

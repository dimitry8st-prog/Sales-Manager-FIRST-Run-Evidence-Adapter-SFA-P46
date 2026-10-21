import pathlib,sys,unittest
p=pathlib.Path(__file__).resolve().parent
sys.path.insert(0,str(p/'source'))
folder=p/'public'
if not folder.exists():
 print('NO_TESTS');sys.exit(1)
suite=unittest.defaultTestLoader.discover(str(folder),pattern='test_*.py')
r=unittest.TextTestRunner(verbosity=2).run(suite)
sys.exit(0 if r.wasSuccessful() and r.testsRun>0 and not r.skipped and not r.expectedFailures and not r.unexpectedSuccesses else 1)

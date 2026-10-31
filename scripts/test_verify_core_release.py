import unittest
from verify_core_release import REQUIRED, validate

class ReleaseEvidence(unittest.TestCase):
    def test_success_and_rejections(self):
        run=dict(head_sha='a'*40,head_branch='main',event='push',status='completed',conclusion='success')
        jobs=[dict(name=n,status='completed',conclusion='success') for n in REQUIRED]
        validate(run,jobs,'a'*40)
        for key,value in [('head_sha','b'*40),('head_branch','candidate'),('event','workflow_dispatch'),('status','in_progress'),('conclusion','cancelled')]:
            with self.subTest(key=key),self.assertRaises(ValueError):validate(dict(run,**{key:value}),jobs,'a'*40)
        for state in ['skipped','failure','cancelled',None]:
            changed=[dict(j) for j in jobs];changed[0]['conclusion']=state
            with self.subTest(state=state),self.assertRaises(ValueError):validate(run,changed,'a'*40)
        for changed in [jobs[:-1],jobs+jobs[:1],[]]:
            with self.assertRaises(ValueError):validate(run,changed,'a'*40)

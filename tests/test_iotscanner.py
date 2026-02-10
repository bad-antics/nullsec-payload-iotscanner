import unittest,sys,os
sys.path.insert(0,os.path.join(os.path.dirname(__file__),"..","src"))
from nullsec_payload_iotscanner.core import IoTScanner

class TestIoT(unittest.TestCase):
    def test_classify(self):
        s=IoTScanner()
        r=s.classify_device("ring-doorbell",[80,443])
        self.assertEqual(r["type"],"camera")
    def test_risk(self):
        s=IoTScanner()
        r=s.assess_iot_risk({"hostname":"camera","default_password":True,"upnp":True,"encrypted":False})
        self.assertEqual(r["risk_level"],"HIGH")

if __name__=="__main__": unittest.main()

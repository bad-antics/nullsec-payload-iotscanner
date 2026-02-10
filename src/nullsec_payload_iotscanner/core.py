"""IoTScanner Engine"""
import json

class IoTScanner:
    IOT_SIGNATURES={
        "smart_bulb":{"ports":[80,443],"keywords":["hue","lifx","wemo","tuya"]},
        "camera":{"ports":[80,554,8080],"keywords":["ipcam","hikvision","dahua","wyze","ring"]},
        "thermostat":{"ports":[80,443],"keywords":["nest","ecobee","honeywell"]},
        "speaker":{"ports":[80,8008,8443],"keywords":["echo","google-home","sonos","alexa"]},
        "lock":{"ports":[80,443],"keywords":["august","schlage","yale","kwikset"]},
    }
    
    def classify_device(self,hostname,open_ports):
        hostname_lower=hostname.lower()
        for device_type,sig in self.IOT_SIGNATURES.items():
            for kw in sig["keywords"]:
                if kw in hostname_lower:
                    return {"type":device_type,"hostname":hostname,"confidence":"HIGH"}
            if any(p in open_ports for p in sig["ports"]):
                return {"type":device_type,"hostname":hostname,"confidence":"LOW"}
        return {"type":"unknown","hostname":hostname,"confidence":"NONE"}
    
    def assess_iot_risk(self,device):
        risks=[]
        if device.get("default_password"): risks.append("Default credentials")
        if not device.get("encrypted"): risks.append("Unencrypted communications")
        if not device.get("updated"): risks.append("Outdated firmware")
        if device.get("upnp"): risks.append("UPnP enabled")
        return {"device":device.get("hostname","unknown"),"risks":risks,"risk_level":"HIGH" if len(risks)>2 else "MEDIUM" if risks else "LOW"}

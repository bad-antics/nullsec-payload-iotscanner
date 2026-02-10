from setuptools import setup,find_packages
setup(name="nullsec-payload-iotscanner",version="2.0.0",author="bad-antics",description="WiFi IoT device scanner and vulnerability assessment",packages=find_packages(where="src"),package_dir={"":"src"},python_requires=">=3.8")

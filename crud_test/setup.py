from setuptools import setup, find_packages

with open("requirements.txt") as f:
	install_requires = f.read().strip().split("\n")

# get version from __version__ variable in crud_test/__init__.py
from crud_test import __version__ as version

setup(
	name="healthpro",
	version=version,
	description="An end to end HRH solution",
	author="Tiberbu",
	author_email="support@tiberbu.com",
	packages=find_packages(),
	zip_safe=False,
	include_package_data=True,
	install_requires=install_requires
)

# Copyright 2016 Cedric Mesnil, Ubinity SAS

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys

if  sys.version_info[0] == 2 and sys.version_info[1] < 7:
    sys.exit("Sorry, Python 2.7 or higher (included 3.x) is only supported ")

if  sys.version_info[0] == 2:
    reqs.append('future')

import setuptools

with open("README.rst", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name='ECPy',
      version='1.2.4',
      description='Pure Pyhton Elliptic Curve Library',
      long_description=long_description,
      keywords='ecdsa eddsa ed25519 ed448 schnorr ecschnorr elliptic curve',
      author='Cedric Mesnil',
      author_email='cslashm@gmail.com',
      url='https://github.com/cslashm/ECPy',
      license='Apache License - Version 2.0',
      provides=['ecpy'],
      packages=['ecpy'],
      package_dir={'ecpy': 'src/ecpy'},
      classifiers=['Programming Language :: Python :: 2.7',
                   'Programming Language :: Python :: 3',
                   'Development Status :: 4 - Beta',
                   'License :: OSI Approved :: Apache Software License',
                   'Topic :: Security :: Cryptography']

)
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

from distutils.core import setup
import sys

if  sys.version_info[0] == 2 and sys.version_info[1] < 7:
    sys.exit("Sorry, Python 2.7 or higher (included 3.x) is only supported ")
    
setup(name='ECPy',
      version='0.8',
      description='Pure Pyhton Elliptic Curve Library',
      author='Cedric Mesnil',
      author_email='cedric.mesnil@ubinity.com',
      url='https://github.com/ubinity',
      packages=['ecpy'],
      package_dir={'ecpy': 'src/ecpy'},
      classifiers=['Programming Language :: Python :: 3 ',
                   'Programming Language :: Python :: 2.7 ',
                   'Development Status :: 4 - Beta',
                   'License :: OSI Approved :: Apache Software License',
                   'Topic :: Security :: Cryptography']
     )

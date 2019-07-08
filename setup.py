import os
from setuptools import find_packages, setup

with open(os.path.join(os.path.dirname(__file__), 'README.md')) as readme:
    README = readme.read()

# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

setup(
    name='restit',
    version='3.3',
    packages=find_packages(),
    include_package_data=True,
    license='BSD License',  # example license
    description='An Advanced DJANGO Rest Framework',
    long_description=README,
    url='https://github.com/istarnes/restit',
    author='Ian Starnes',
    author_email='ian+restit@311labs.com',
    classifiers=[
        'Environment :: Web Environment',
        'Framework :: Django',
        'Framework :: Django :: rest',  # replace "X.Y" as appropriate
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',  # example license
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
    ],
)
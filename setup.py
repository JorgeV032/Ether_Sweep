from setuptools import setup

setup(
    name='ether_sweep',
    version='1.0',
    py_modules=['ether_sweep'],
    entry_points={
        'console_scripts': [
            'ether_sweep=ether_sweep:main',
        ],
    },
    install_requires=[
        'scapy',
        'colorama'
    ]
)

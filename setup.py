from setuptools import setup, find_packages

from consullock.configuration import PACKAGE_NAME, DESCRIPTION, EXECUTABLE_NAME

try:
    from pypandoc import convert
    def read_markdown(file: str) -> str:
        return convert(file, "rst")
except ImportError:
    def read_markdown(file: str) -> str:
        return open(file, "r").read()

setup(
    name=PACKAGE_NAME,
    version="1.0.0",
    packages=find_packages(exclude=["tests"]),
    install_requires=open("requirements.txt", "r").readlines(),
    url="https://github.com/wtsi-hgi/consul-lock",
    license="MIT",
    description=DESCRIPTION,
    long_description=read_markdown("README.md"),
    entry_points={
        "console_scripts": [
            f"{EXECUTABLE_NAME}=consullock.cli:entrypoint"
        ]
    },
    zip_safe=True
)

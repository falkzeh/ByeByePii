import setuptools
from pathlib import Path

this_directory = Path(__file__).parent
long_description = (this_directory / "readme.md").read_text()

setuptools.setup(
    name="ByeByePii",
    version="0.0.2",
    author="Falk Z.",
    description="A package for hashing personal identifiable information (PII).",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=setuptools.find_packages(),
)

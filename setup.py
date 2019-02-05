import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="flowmeter",
    version="0.0.2",
    author="Kyle Topasna",
    author_email="kyle.topasna@gmail.com",
    description="A tool for deriving statistical features from pcap data.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/alekzandr/flowmeter",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
)
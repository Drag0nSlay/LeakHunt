from setuptools import find_packages, setup

setup(
    name="leakhunt",
    version="1.0.0",
    description="Independent secret discovery tool for URLs and local files",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[],
    entry_points={"console_scripts": ["leakhunt=leakhunt.cli:main"]},
    python_requires=">=3.9",
)
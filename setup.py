from setuptools import find_packages, setup

setup(
    name="leakhunt",
    version="2.2.0",
    description="Independent secret discovery tool for URLs and local files",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "requests>=2.31.0",
        "tenacity>=8.2.3",
        "tqdm>=4.66.0",
        "pyyaml>=6.0",
    ],
    entry_points={"console_scripts": ["leakhunt=leakhunt.cli:main"]},
    python_requires=">=3.9",
)

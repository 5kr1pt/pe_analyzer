from setuptools import setup, find_packages

setup(
    name="pe_analyzer",
    version="1.0.0",
    description="Analisador estático de arquivos executáveis Windows (PE Files)",
    author="KRPT",
    author_email="pgwerneck5@outlook.com",
    packages=find_packages(),
    install_requires=[
        "pefile>=2019.4.18",
    ],
    entry_points={
        'console_scripts': [
            'pe_analyzer=pe_analyzer.main:main'
        ],
    },
)
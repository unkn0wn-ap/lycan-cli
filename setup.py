"""
setup.py — Lycan Security Agent
Instala el agente como paquete editable con entry-point 'lycan'.

    pip install -e .        → registra `lycan` en PATH
    pip install -e .[dev]   → añade dependencias de desarrollo
"""
from setuptools import setup, find_packages
from pathlib import Path

HERE = Path(__file__).parent
README = (HERE / "README.md").read_text(encoding="utf-8") if (HERE / "README.md").exists() else ""

setup(
    name="lycan-security-agent",
    version="1.1.0",
    description="Lycan Security — Local Scan Agent (BYOI)",
    long_description=README,
    long_description_content_type="text/markdown",
    author="Lycan Security",
    python_requires=">=3.10",
    # The agent is a single-file module; we expose it directly
    py_modules=["agent"],
    install_requires=[
        "supabase>=2.5.0",
        "python-dotenv>=1.0.1",
        "pydantic>=2.7.0",
        "netifaces>=0.11.0",
        "requests>=2.32.0",
        "rich>=13.7.0",
        "packaging>=23.0",
    ],
    extras_require={
        "dev": ["pytest", "black", "ruff"],
    },
    entry_points={
        "console_scripts": [
            # `lycan` command → agent.main()
            "lycan = agent:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
)

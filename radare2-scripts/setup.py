from setuptools import setup

import radare2_scripts as scale

setup(
    name="snake-{}".format(scale.NAME),
    version=scale.VERSION,
    packages=[
        "snake_{}".format(scale.NAME)
    ],
    package_dir={
        "snake_{}".format(scale.NAME): scale.NAME
    },
    install_requires=[
        "snake",
        "r2pipe"
    ],

    entry_points={
        "snake.scales": [
            "{0} = snake_{0}".format(scale.NAME),
        ]
    },

    include_package_data=True,

    zip_safe=False,

    author=scale.AUTHOR,
    author_email=scale.AUTHOR_EMAIL,
    description=scale.DESCRIPTION,
    license=scale.LICENSE,
    url=scale.URL
)

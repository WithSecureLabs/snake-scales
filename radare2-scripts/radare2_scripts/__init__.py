from snake.scale import scale


NAME = "radare2_scripts"
VERSION = "1.1"

AUTHOR = "Alex Kornitzer"
AUTHOR_EMAIL = "alex.kornitzer@countercept.com"

DESCRIPTION = "a module to run radare2 based scripts on files"

LICENSE = "https://github.com/countercept/snake-scales/blob/master/LICENSE"

URL = "https://github.com/countercept/snake-scales"


__scale__ = scale(
    name=NAME,
    description=DESCRIPTION,
    version=VERSION,
    author=AUTHOR,
    supports=[
    ],
)

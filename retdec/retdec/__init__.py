from snake.scale import FileType, scale


NAME = "retdec"
VERSION = "1.0"

AUTHOR = "Alex Kornitzer"
AUTHOR_EMAIL = "alex.kornitzer@countercept.com"

DESCRIPTION = "a module to interface with retdec (online or local)"

LICENSE = "https://github.com/countercept/snake-scales/blob/master/LICENSE"

URL = "https://github.com/countercept/snake-scales"


__scale__ = scale(
    name=NAME,
    description=DESCRIPTION,
    version=VERSION,
    author=AUTHOR,
    supports=[
        FileType.FILE
    ],
)

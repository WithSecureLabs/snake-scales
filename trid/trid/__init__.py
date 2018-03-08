from snake.scale import scale, FileType


NAME = "trid"
VERSION = "1.0"

AUTHOR = "Matt Watkins"
AUTHOR_EMAIL = "matthew.watkins@countercept.com"

DESCRIPTION = "a module to execute trid on files"

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

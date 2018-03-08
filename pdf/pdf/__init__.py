from snake.scale import FileType, scale


NAME = "pdf"
VERSION = "1.0"

AUTHOR = "Matt Watkins"
AUTHOR_EMAIL = "matthew.watkins@countercept.com"

DESCRIPTION = "parse the file with pdf utilities"

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

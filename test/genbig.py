import sys

c1984 = """\
It was a bright cold day in April, and the clocks
were striking thirteen. Winston Smith, his chin nuzzled
into his breast in an effort to escape the vile wind,
slipped quickly through the glass doors of Victory
Mansions, though not quickly enough to prevent a
swirl of gritty dust from entering along with him.
-----------------------------------------------------
"""

SIZE = int(sys.argv[2])

with open(sys.argv[1], "w") as f:
    s = 0
    while s < SIZE:
        f.write(c1984)
        s += len(c1984)

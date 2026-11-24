# SPDX-License-Identifier: MIT
"""Recreate fonts/tagged-fallback.ttf with FontTools 4.61.1.

Usage: make-tagged-fallback.py OUTPUT.ttf
"""

import sys

from fontTools.fontBuilder import FontBuilder
from fontTools.pens.ttGlyphPen import TTGlyphPen

if len(sys.argv) != 2:
    sys.exit("Usage: make-tagged-fallback.py OUTPUT.ttf")


def boxed_question_mark():
    pen = TTGlyphPen(None)
    for contour in (
        ((70, 0), (70, 700), (630, 700), (630, 0)),
        ((125, 55), (575, 55), (575, 645), (125, 645)),
        ((320, 265), (320, 352), (405, 408), (430, 455), (430, 488),
         (410, 518), (380, 532), (324, 532), (290, 515), (267, 483),
         (212, 512), (245, 559), (305, 592), (400, 592), (458, 567),
         (492, 517), (500, 478), (491, 435), (463, 389), (383, 330),
         (383, 265)),
        ((315, 124), (315, 199), (389, 199), (389, 124)),
    ):
        pen.moveTo(contour[0])
        for point in contour[1:]:
            pen.lineTo(point)
        pen.closePath()
    return pen.glyph()


glyphs = [".notdef", "uniFFFD"]
font = FontBuilder(1000, isTTF=True)
font.setupGlyphOrder(glyphs)
font.setupCharacterMap({0xFFFD: "uniFFFD"})
font.setupGlyf({name: boxed_question_mark() for name in glyphs})
font.setupHorizontalMetrics({name: (700, 70) for name in glyphs})
font.setupHorizontalHeader(ascent=800, descent=-200)
font.setupNameTable({
    "familyName": "SBOM Missing Glyph",
    "styleName": "Regular",
    "uniqueFontIdentifier": "SBOMMissingGlyph-1",
    "fullName": "SBOM Missing Glyph",
    "psName": "SBOMMissingGlyph-Regular",
})
font.setupOS2(sTypoAscender=800, sTypoDescender=-200, usWinAscent=800, usWinDescent=200)
font.setupPost(keepGlyphNames=False)
font.font.recalcTimestamp = False
font.setupHead(created=3786912000, modified=3786912000)
font.save(sys.argv[1])

// SPDX-License-Identifier: MIT

//go:build taggedpdf && !ios

package pdf

import "embed"

//go:embed bundle/darwin_arm64/typst.gz bundle/darwin_arm64/NotoSansCJKtc-Regular.otf.gz bundle/darwin_arm64/NotoEmoji.ttf.gz
//go:embed bundle/darwin_arm64/LICENSE bundle/darwin_arm64/NOTICE bundle/darwin_arm64/NotoSansCJKtc-OFL.txt bundle/darwin_arm64/NotoEmoji-OFL.txt
var taggedAssets embed.FS

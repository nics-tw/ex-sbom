// SPDX-License-Identifier: MIT

//go:build taggedpdf && !android

package pdf

import "embed"

//go:embed bundle/linux_arm64/typst.gz bundle/linux_arm64/NotoSansCJKtc-Regular.otf.gz bundle/linux_arm64/NotoEmoji.ttf.gz
//go:embed bundle/linux_arm64/LICENSE bundle/linux_arm64/NOTICE bundle/linux_arm64/NotoSansCJKtc-OFL.txt bundle/linux_arm64/NotoEmoji-OFL.txt
var taggedAssets embed.FS

// SPDX-License-Identifier: MIT

//go:build taggedpdf && !android

package pdf

import "embed"

//go:embed bundle/linux_amd64/typst.gz bundle/linux_amd64/NotoSansCJKtc-Regular.otf.gz bundle/linux_amd64/NotoEmoji.ttf.gz
//go:embed bundle/linux_amd64/typst.sha256 bundle/linux_amd64/NotoSansCJKtc-Bold.otf.gz
//go:embed bundle/linux_amd64/LICENSE bundle/linux_amd64/NOTICE bundle/linux_amd64/NotoSansCJKtc-OFL.txt bundle/linux_amd64/NotoEmoji-OFL.txt
var taggedAssets embed.FS

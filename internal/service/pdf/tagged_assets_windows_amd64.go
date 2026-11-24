// SPDX-License-Identifier: MIT

//go:build taggedpdf

package pdf

import "embed"

//go:embed bundle/windows_amd64/typst.exe.gz bundle/windows_amd64/NotoSansCJKtc-Regular.otf.gz bundle/windows_amd64/NotoEmoji.ttf.gz
//go:embed bundle/windows_amd64/typst.sha256 bundle/windows_amd64/NotoSansCJKtc-Bold.otf.gz
//go:embed bundle/windows_amd64/LICENSE bundle/windows_amd64/NOTICE bundle/windows_amd64/NotoSansCJKtc-OFL.txt bundle/windows_amd64/NotoEmoji-OFL.txt
var taggedAssets embed.FS

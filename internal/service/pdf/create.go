package pdf

import (
	"strconv"
	"time"

	"github.com/johnfercher/maroto/v2/pkg/components/line"
	"github.com/johnfercher/maroto/v2/pkg/components/page"
	"github.com/johnfercher/maroto/v2/pkg/components/row"
	"github.com/johnfercher/maroto/v2/pkg/components/text"
	"github.com/johnfercher/maroto/v2/pkg/config"
	"github.com/johnfercher/maroto/v2/pkg/consts/align"
	"github.com/johnfercher/maroto/v2/pkg/consts/fontstyle"
	"github.com/johnfercher/maroto/v2/pkg/core"
	"github.com/johnfercher/maroto/v2/pkg/props"

	"github.com/johnfercher/maroto/v2"
)

type (
	ReportData struct {
		OverviewInfo         OverviewInfo
		TotalVulnerabilities int
		CVSSLevels           CVSSLevels
		EPSSLevels           EPSSLevels
		LEVLevels            LEVLevels
		ComponentInfos       []ComponentInfo
		VulnInfos            []VulnInfos
	}

	OverviewInfo struct {
		Total                       int
		Direct                      int
		DirectWithVulnerabilities   int
		DWVNames                    []string
		Indirect                    int
		IndirectWithVulnerabilities int
		IDWVNames                   []string
	}

	CVSSLevels struct {
		Low      int
		Medium   int
		High     int
		Critical int
	}

	EPSSLevels struct {
		MoreThan10Percent int
		MoreThan50Percent int
		MoreThan90Percent int
	}

	LEVLevels struct {
		MoreThan10Percent int
		MoreThan50Percent int
		MoreThan90Percent int
	}

	ComponentInfo struct {
		Name     string
		Low      int
		Medium   int
		High     int
		Critical int
	}

	VulnInfos struct {
		ID      string
		Summary string
		CVSS    string
		EPSS    string
		LEV     string

		SuggestFixVersion string
		OtherFixVersions  string

		Details string
	}
)

var (
	contentL = props.Text{
		Align:  align.Left,
		Top:    16,
		Size:   12,
		Family: "courier",
	}
	contentR = props.Text{
		Align:  align.Right,
		Top:    16,
		Size:   12,
		Family: "courier",
	}
)

func GetMaroto(infos []ComponentInfo, vulns []VulnInfos) core.Maroto {
	result := ReportData{
		OverviewInfo: OverviewInfo{
			Total:                       100,
			Direct:                      60,
			DirectWithVulnerabilities:   30,
			DWVNames:                    []string{"component1", "component2", "component3"},
			Indirect:                    40,
			IndirectWithVulnerabilities: 20,
			IDWVNames:                   []string{"component4", "component5", "component6"},
		},
		TotalVulnerabilities: 74,
		CVSSLevels: CVSSLevels{
			Low:      10,
			Medium:   20,
			High:     30,
			Critical: 14,
		},
		EPSSLevels: EPSSLevels{
			MoreThan10Percent: 40,
			MoreThan50Percent: 20,
			MoreThan90Percent: 4,
		},
		LEVLevels: LEVLevels{
			MoreThan10Percent: 30,
			MoreThan50Percent: 10,
			MoreThan90Percent: 4,
		},
		ComponentInfos: infos,
		VulnInfos:      vulns,
	}

	cfg := config.NewBuilder().
		WithPageNumber(props.PageNumber{Place: "right_top"}).
		WithDebug(false).
		Build()

	mrt := maroto.New(cfg)
	m := maroto.NewMetricsDecorator(mrt)

	m.AddPages(
		page.New().Add(
			row.New().Add(
				text.NewCol(
					4,
					"",
				),
				text.NewCol(
					4,
					"Analysis Report",
					props.Text{
						Align:  align.Center,
						Top:    13,
						Size:   18,
						Style:  fontstyle.Bold,
						Family: "courier",
					},
				),
				text.NewCol(
					4,
					time.Now().Format("2006-01-02 15:04:05"),
					props.Text{
						Align:  align.Center,
						Top:    17,
						Family: "courier",
					},
				),
			),
			// for indent usage
			row.New(2).Add(),
			row.New().Add(
				line.NewCol(
					12,
				),
			),
			row.New(6).Add(
				text.NewCol(
					1,
					"",
				),
				text.NewCol(
					5,
					"Overview:",
					props.Text{
						Align:  align.Left,
						Top:    13,
						Size:   14,
						Style:  fontstyle.Bold,
						Family: "courier",
					},
				),
			),
			row.New(8).Add(
				text.NewCol(
					2,
					"",
				),
				text.NewCol(
					7,
					"Total Components: ",
					contentL,
				),
				text.NewCol(
					2,
					strconv.Itoa(result.OverviewInfo.Total),
					contentR,
				),
			),
			row.New(6).Add(
				text.NewCol(
					2,
					"",
				),
				text.NewCol(
					7,
					"Direct Components: ",
					contentL,
				),
				text.NewCol(
					2,
					strconv.Itoa(result.OverviewInfo.Direct),
					contentR,
				),
			),
			row.New(6).Add(
				text.NewCol(
					2,
					"",
				),
				text.NewCol(
					7,
					"Direct Components with Vulnerabilities: ",
					contentL,
				),
				text.NewCol(
					2,
					strconv.Itoa(result.OverviewInfo.DirectWithVulnerabilities),
					contentR,
				),
			),
			row.New(6).Add(
				text.NewCol(
					2,
					"",
				),
				text.NewCol(
					7,
					"Indirect Components: ",
					contentL,
				),
				text.NewCol(
					2,
					strconv.Itoa(result.OverviewInfo.Indirect),
					contentR,
				),
			),
			row.New(6).Add(
				text.NewCol(
					2,
					"",
				),
				text.NewCol(
					7,
					"Indirect Components with Vulnerabilities: ",
					contentL,
				),
				text.NewCol(
					2,
					strconv.Itoa(result.OverviewInfo.IndirectWithVulnerabilities),
					contentR,
				),
			),
			row.New(6).Add(
				text.NewCol(
					2,
					"",
				),
				text.NewCol(
					7,
					"Total Vulnerabilities: ",
					contentL,
				),
				text.NewCol(
					2,
					strconv.Itoa(result.TotalVulnerabilities),
					contentR,
				),
			),
			row.New(12).Add(
				text.NewCol(
					1,
					"",
				),
				text.NewCol(
					5,
					"CVSS Distribution:",
					props.Text{
						Align:  align.Left,
						Top:    13,
						Size:   14,
						Style:  fontstyle.Bold,
						Family: "courier",
					},
				),
			),
			row.New(8).Add(
				text.NewCol(
					2,
					"",
				),
				text.NewCol(
					7,
					"Low: ",
					contentL,
				),
				text.NewCol(
					2,
					strconv.Itoa(result.CVSSLevels.Low),
					contentR,
				),
			),
			row.New(6).Add(
				text.NewCol(
					2,
					"",
				),
				text.NewCol(
					7,
					"Medium: ",
					contentL,
				),
				text.NewCol(
					2,
					strconv.Itoa(result.CVSSLevels.Medium),
					contentR,
				),
			),
			row.New(6).Add(
				text.NewCol(
					2,
					"",
				),
				text.NewCol(
					7,
					"High: ",
					contentL,
				),
				text.NewCol(
					2,
					strconv.Itoa(result.CVSSLevels.High),
					contentR,
				),
			),
			row.New(6).Add(
				text.NewCol(
					2,
					"",
				),
				text.NewCol(
					7,
					"Critical: ",
					contentL,
				),
				text.NewCol(
					2,
					strconv.Itoa(result.CVSSLevels.Critical),
					contentR,
				),
			),
			row.New(12).Add(
				text.NewCol(
					1,
					"",
				),
				text.NewCol(
					5,
					"EPSS Accumulation:",
					props.Text{
						Align:  align.Left,
						Top:    13,
						Size:   14,
						Style:  fontstyle.Bold,
						Family: "courier",
					},
				),
			),
			row.New(8).Add(
				text.NewCol(
					2,
					"",
				),
				text.NewCol(
					7,
					"More than 10%: ",
					contentL,
				),
				text.NewCol(
					2,
					strconv.Itoa(result.EPSSLevels.MoreThan10Percent),
					contentR,
				),
			),
			row.New(6).Add(
				text.NewCol(
					2,
					"",
				),
				text.NewCol(
					7,
					"More than 50%: ",
					contentL,
				),
				text.NewCol(
					2,
					strconv.Itoa(result.EPSSLevels.MoreThan50Percent),
					contentR,
				),
			),
			row.New(6).Add(
				text.NewCol(
					2,
					"",
				),
				text.NewCol(
					7,
					"More than 90%: ",
					contentL,
				),
				text.NewCol(
					2,
					strconv.Itoa(result.EPSSLevels.MoreThan90Percent),
					contentR,
				),
			),
			row.New(12).Add(
				text.NewCol(
					1,
					"",
				),
				text.NewCol(
					5,
					"LEV Accumulation:",
					props.Text{
						Align:  align.Left,
						Top:    13,
						Size:   14,
						Style:  fontstyle.Bold,
						Family: "courier",
					},
				),
			),
			row.New(8).Add(
				text.NewCol(
					2,
					"",
				),
				text.NewCol(
					7,
					"More than 10%: ",
					contentL,
				),
				text.NewCol(
					2,
					strconv.Itoa(result.LEVLevels.MoreThan10Percent),
					contentR,
				),
			),
			row.New(6).Add(
				text.NewCol(
					2,
					"",
				),
				text.NewCol(
					7,
					"More than 50%: ",
					contentL,
				),
				text.NewCol(
					2,
					strconv.Itoa(result.LEVLevels.MoreThan50Percent),
					contentR,
				),
			),
			row.New(6).Add(
				text.NewCol(
					2,
					"",
				),
				text.NewCol(
					7,
					"More than 90%: ",
					contentL,
				),
				text.NewCol(
					2,
					strconv.Itoa(result.LEVLevels.MoreThan90Percent),
					contentR,
				),
			),
		),
	)

	componentRows := []core.Row{}
	componentRows = append(componentRows, row.New(8).Add(
		text.NewCol(
			1,
			"",
		),
		text.NewCol(
			2,
			"Name: ",
			contentL,
		),
		text.NewCol(
			2,
			"Low",
			contentL,
		),
		text.NewCol(
			2,
			"Medium",
			contentL,
		),
		text.NewCol(
			2,
			"High",
			contentL,
		),
		text.NewCol(
			2,
			"Critical",
			contentL,
		),
	))

	for _, info := range result.ComponentInfos {
		// since the name may be too long, make a a single line and the score will be the next line
		componentRows = append(componentRows, row.New(6).Add(
			text.NewCol(
				1,
				"",
			),
			text.NewCol(
				4,
				info.Name,
				contentL,
			)))

		componentRows = append(componentRows, row.New(6).Add(
			text.NewCol(
				3,
				"",
			),
			text.NewCol(
				2,
				strconv.Itoa(info.Low),
				contentL,
			),
			text.NewCol(
				2,
				strconv.Itoa(info.Medium),
				contentL,
			),
			text.NewCol(
				2,
				strconv.Itoa(info.High),
				contentL,
			),
			text.NewCol(
				2,
				strconv.Itoa(info.Critical),
				contentL,
			),
		))
	}

	m.AddPages(
		page.New().Add(
			row.New().Add(
				text.NewCol(
					1,
					"",
				),
				text.NewCol(
					10,
					"Components with Vulnerabilities Overview:",
					props.Text{
						Align:  align.Center,
						Top:    13,
						Size:   14,
						Style:  fontstyle.Bold,
						Family: "courier",
					},
				),
			),
		).Add(
			componentRows...,
		),
	)

	for _, vuln := range result.VulnInfos {
		m.AddPages(
			page.New().Add(
				row.New().Add(
					text.NewCol(
						1,
						"",
					),
					text.NewCol(
						10,
						"Appendix: "+vuln.ID+" Vulnerability Details ",
						props.Text{
							Align:  align.Center,
							Top:    13,
							Size:   14,
							Style:  fontstyle.Bold,
							Family: "courier",
						},
					),
				),
				row.New(6).Add(
					text.NewCol(
						1,
						"",
					),
					text.NewCol(
						4,
						"Summary: ",
						contentL,
					),
				),
				row.New(6).Add(
					text.NewCol(
						2,
						"",
					),
					text.NewCol(
						15,
						vuln.Summary,
						contentL,
					),
				),
				row.New(6).Add(
					text.NewCol(
						1,
						"",
					),
					text.NewCol(
						4,
						"CVSS: ",
						contentL,
					),
					text.NewCol(
						6,
						vuln.CVSS,
						contentR,
					),
				),
				row.New(6).Add(
					text.NewCol(
						1,
						"",
					),
					text.NewCol(
						4,
						"EPSS: ",
						contentL,
					),
					text.NewCol(
						6,
						vuln.EPSS,
						contentR,
					),
				),
				row.New(6).Add(
					text.NewCol(
						1,
						"",
					),
					text.NewCol(
						4,
						"LEV: ",
						contentL,
					),
					text.NewCol(
						6,
						vuln.LEV,
						contentR,
					),
				),
				row.New(6).Add(
					text.NewCol(
						1,
						"",
					),
					text.NewCol(
						4,
						"Suggested Fix Version: ",
						contentL,
					),
					text.NewCol(
						6,
						vuln.SuggestFixVersion,
						contentR,
					),
				),
				row.New(6).Add(
					text.NewCol(
						1,
						"",
					),
					text.NewCol(
						4,
						"Other Fix Versions: ",
						contentL,
					),
					text.NewCol(
						6,
						vuln.OtherFixVersions,
						contentR,
					),
				),
				row.New(6).Add(),
				row.New(6).Add(
					text.NewCol(
						1,
						"",
					),
					text.NewCol(
						15,
						"Details: ",
						contentL,
					),
				),
				row.New(6).Add(
					text.NewCol(
						1,
						"",
					),
					text.NewCol(
						15,
						vuln.Details,
						contentL,
					),
				),
			),
		)
	}

	return m
}

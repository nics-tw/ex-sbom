package pdf

import (
	ssbom "ex-sbom/internal/service/sbom"
	"fmt"
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

func GetFileName(bomName string) string {
	now := time.Now()
	return fmt.Sprintf("%s_report_%s.pdf", bomName, now.Format("20060102_150405"))
}

func GetReportData(bom ssbom.FormattedSBOM) ReportData {
	var result ReportData

	// Overview
	result.OverviewInfo.Total = len(bom.Components)
	result.OverviewInfo.Direct = 0
	result.OverviewInfo.DirectWithVulnerabilities = 0
	result.OverviewInfo.DWVNames = []string{}
	result.OverviewInfo.Indirect = 0
	result.OverviewInfo.IndirectWithVulnerabilities = 0
	result.OverviewInfo.IDWVNames = []string{}

	// Vulnerability and component info
	result.TotalVulnerabilities = 0
	result.CVSSLevels = CVSSLevels{}
	result.EPSSLevels = EPSSLevels{}
	result.LEVLevels = LEVLevels{}
	result.ComponentInfos = []ComponentInfo{}
	result.VulnInfos = []VulnInfos{}

	for name, comp := range bom.ComponentInfo {
		cInfo := ComponentInfo{
			Name:     comp.Name,
			Low:      0,
			Medium:   0,
			High:     0,
			Critical: 0,
		}

		if level, ok := bom.ComponentToLevel[name]; ok && level == 0 {
			result.OverviewInfo.Direct++
			if comp.VulnNumber > 0 {
				result.OverviewInfo.DirectWithVulnerabilities++
				result.OverviewInfo.DWVNames = append(result.OverviewInfo.DWVNames, comp.Name)
			}
		} else {
			result.OverviewInfo.Indirect++
			if comp.VulnNumber > 0 {
				result.OverviewInfo.IndirectWithVulnerabilities++
				result.OverviewInfo.IDWVNames = append(result.OverviewInfo.IDWVNames, comp.Name)
			}
		}

		for _, v := range comp.Vulns {
			result.TotalVulnerabilities++
			// Parse CVSS score
			cvss, _ := strconv.ParseFloat(v.CVSSScore, 64)
			switch {
			case cvss >= 9.0:
				cInfo.Critical++
				result.CVSSLevels.Critical++
			case cvss >= 7.0:
				cInfo.High++
				result.CVSSLevels.High++
			case cvss >= 4.0:
				cInfo.Medium++
				result.CVSSLevels.Medium++
			case cvss > 0.0:
				cInfo.Low++
				result.CVSSLevels.Low++
			}

			// Parse EPSS and LEV (as float, if present)
			epss, _ := strconv.ParseFloat(v.EPSS, 64)
			lev, _ := strconv.ParseFloat(v.LEV, 64)
			if epss >= 0.9 {
				result.EPSSLevels.MoreThan90Percent++
			} else if epss >= 0.5 {
				result.EPSSLevels.MoreThan50Percent++
			} else if epss >= 0.1 {
				result.EPSSLevels.MoreThan10Percent++
			}
			if lev >= 0.9 {
				result.LEVLevels.MoreThan90Percent++
			} else if lev >= 0.5 {
				result.LEVLevels.MoreThan50Percent++
			} else if lev >= 0.1 {
				result.LEVLevels.MoreThan10Percent++
			}

			// Add to VulnInfos
			result.VulnInfos = append(result.VulnInfos, VulnInfos{
				ID:                v.ID,
				Summary:           v.Summary,
				CVSS:              v.CVSSScore,
				EPSS:              v.EPSS,
				LEV:               v.LEV,
				SuggestFixVersion: v.SuggestFixVersion,
				OtherFixVersions:  v.OtherFixVersions,
				Details:           v.Details,
			})
		}

		result.ComponentInfos = append(result.ComponentInfos, cInfo)
	}

	return result
}

func GetMaroto(result ReportData) core.Maroto {
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
						1,
						"",
					),
					text.NewCol(
						8,
						vuln.Summary,
						contentL,
					),
				),
				row.New(6).Add(),
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
						10,
						vuln.Details,
						contentL,
					),
				),
			),
		)
	}

	return m
}

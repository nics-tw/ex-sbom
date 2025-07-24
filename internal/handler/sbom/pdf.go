package sbom

import (
	"ex-sbom/internal/service/pdf"
	ssbom "ex-sbom/internal/service/sbom"
	"fmt"

	"github.com/gin-gonic/gin"
)

func validate(c *gin.Context) (string, ssbom.FormattedSBOM, error) {
	name := c.Param("name")
	if name == "" {
		return "", ssbom.FormattedSBOM{}, fmt.Errorf("component name is required")
	}

	bom, ok := ssbom.SBOMs[name]
	if !ok {
		return "", ssbom.FormattedSBOM{}, fmt.Errorf("component %s not found", name)
	}

	return name, bom, nil
}

func CreateReportPDF(c *gin.Context) {
	name, bom, err := validate(c)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	d := pdf.GetReportData(bom)

	m := pdf.GetMaroto(d)

	doc, err := m.Generate()
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to create PDF"})
		return
	}

	err = doc.Save(pdf.GetFileName(name))
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to save PDF"})
		return
	}

	c.JSON(200, gin.H{
		"message": "PDF report created successfully",
		"file":    pdf.GetFileName(name),
	})
}

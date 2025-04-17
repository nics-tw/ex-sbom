package kev

const (
	KevJsonFile = "kev_2025_04_17.json"
)

type (
	KEV struct {
		TItle          string `json:"title"`
		CatalogVersion string `json:"catalogVersion"`
		DateReleased   string `json:"dateReleased"`
		Count          int    `json:"count"`
		Vulns          []Vuln `json:"vulnerabilities"`
	}

	Vuln struct {
		CveID         string `json:"cveID"`
		VendorProject string `json:"vendorProject"`
		Product	   string `json:"product"`
		VulnName	 string `json:"vulnerabilityName"`
		DateAdded	 string `json:"dateAdded"`
		ShortDesp string `json:"shortDescription"`
		RequiredAction string `json:"requiredAction"`
		DueDate string `json:"dueDate"`
		KnownRansonwareCampaignUse string `json:"knownRansomwareCampaignUse"`
		Notes string `json:"notes"`
		Cwes []string `json:"cwes"`
	}
)

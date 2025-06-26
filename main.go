package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/rivo/tview"
)

type sourcePackageCve struct {
	CveId                string  `json:"cveId"`
	BaseScore            float32 `json:"baseScore"`
	VectorString         string  `json:"vectorString"`
	SourcePackageName    string  `json:"sourcePackageName"`
	SourcePackageVersion string  `json:"sourcePackageVersion"`
	GardenlinuxVersion   string  `json:"gardenlinuxVersion"`
	IsVulnerable         bool    `json:"isVulnerable"`
	CvePublishedDate     string  `json:"cvePublishedDate"`
}

func main() {
	app := tview.NewApplication()
	flex := tview.NewFlex()
	table := tview.NewTable()

	dropdown := tview.NewDropDown().
		SetLabel("Garden Linux version: ").
		SetOptions([]string{"1877.0", "1592.10", "1592.9"}, func(text string, index int) {
			table.Clear()
			url := "https://glvd.ingress.glvd.gardnlinux.shoot.canary.k8s-hana.ondemand.com/v1/cves/" + text
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				log.Fatal(err)
			}
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				log.Fatal(err)
			}
			defer res.Body.Close()
			body, _ := io.ReadAll(res.Body)
			var results []sourcePackageCve
			err = json.Unmarshal(body, &results)
			if err != nil {
				log.Fatal(err)
			}

			for i, cve := range results {
				table.SetCellSimple(i, 0, cve.CveId)
				table.SetCellSimple(i, 1, fmt.Sprintf("%.1f", cve.BaseScore))
				table.SetCellSimple(i, 2, cve.SourcePackageName)
				table.SetCellSimple(i, 3, cve.SourcePackageVersion)
			}
		})

	flex.AddItem(dropdown, 0, 1, true)
	flex.AddItem(table, 0, 1, false)

	if err := app.SetRoot(flex, true).EnableMouse(true).Run(); err != nil {
		panic(err)
	}
}

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
	list := tview.NewList()

	url := "https://glvd.ingress.glvd.gardnlinux.shoot.canary.k8s-hana.ondemand.com/v1/cves/1592.10"

	req, _ := http.NewRequest("GET", url, nil)

	res, _ := http.DefaultClient.Do(req)

	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)

	var results []sourcePackageCve
	err := json.Unmarshal(body, &results)
	if err != nil {
		log.Fatal(err)
	}

	var foo rune = 'a'
	for _, y := range results {
		fmt.Println(y)
		list.AddItem(y.CveId, y.SourcePackageName, foo, nil)
		foo++
	}

	if err := app.SetRoot(list, true).EnableMouse(true).Run(); err != nil {
		panic(err)
	}
}

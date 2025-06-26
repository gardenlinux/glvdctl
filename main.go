package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/urfave/cli/v3"
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
	cmd := &cli.Command{
		Name:                  "glvdctl",
		EnableShellCompletion: true,
		Commands: []*cli.Command{
			{
				Name:    "cve",
				Aliases: []string{"cves"},
				Usage:   "list cves for a Garden Linux release",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					url := "https://glvd.ingress.glvd.gardnlinux.shoot.canary.k8s-hana.ondemand.com/v1/cves/" + cmd.Args().Get(0)
					req, _ := http.NewRequest("GET", url, nil)

					res, _ := http.DefaultClient.Do(req)

					defer res.Body.Close()
					body, _ := io.ReadAll(res.Body)

					fmt.Println(res)
					fmt.Println(string(body))

					var results []sourcePackageCve
					err := json.Unmarshal(body, &results)
					if err != nil {
						log.Fatal(err)
					}

					for _, y := range results {
						fmt.Println(y)
					}

					return nil
				},
			},
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}

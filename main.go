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

	"github.com/fatih/color"
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

type CveDetail struct {
	CveId                     string   `json:"cveId"`
	VulnStatus                string   `json:"vulnStatus"`
	Description               string   `json:"description"`
	CvePublishedDate          string   `json:"cvePublishedDate"`
	CveModifiedDate           string   `json:"cveModifiedDate"`
	CveIngestedDate           string   `json:"cveIngestedDate"`
	KernelLtsVersion          []string `json:"kernelLtsVersion"`
	KernelFixedVersion        []string `json:"kernelFixedVersion"`
	KernelIsFixed             []bool   `json:"kernelIsFixed"`
	KernelIsRelevantSubsystem []bool   `json:"kernelIsRelevantSubsystem"`
	Distro                    []string `json:"distro"`
	DistroVersion             []string `json:"distroVersion"`
	IsVulnerable              []bool   `json:"isVulnerable"`
	SourcePackageName         []string `json:"sourcePackageName"`
	SourcePackageVersion      []string `json:"sourcePackageVersion"`
	VersionFixed              []string `json:"versionFixed"`
	BaseScoreV40              float32  `json:"baseScoreV40"`
	BaseScoreV31              float32  `json:"baseScoreV31"`
	BaseScoreV30              float32  `json:"baseScoreV30"`
	BaseScoreV2               float32  `json:"baseScoreV2"`
	VectorStringV40           string   `json:"vectorStringV40"`
	VectorStringV31           string   `json:"vectorStringV31"`
	VectorStringV30           string   `json:"vectorStringV30"`
	VectorStringV2            string   `json:"vectorStringV2"`
}

func printSourcePackageCveTable(cves []sourcePackageCve) {
	value := color.New(color.FgHiWhite).SprintFunc()
	important := color.New(color.FgHiRed, color.Bold).SprintFunc()

	// Print table header (no color for best alignment)
	fmt.Printf("%-16s %-13s %-18s %-8s %6s %-4s %s\n",
		"CVE ID",
		"Package",
		"Source Ver",
		"GL Ver",
		"Score",
		"Vuln",
		"Published",
	)

	// Print each row
	for _, cve := range cves {
		vuln := "no"
		if cve.IsVulnerable {
			vuln = important("YES")
		}
		fmt.Printf("%-16s %-13s %-18s %-8s %6.2f %-4s %s\n",
			value(cve.CveId),
			value(cve.SourcePackageName),
			value(cve.SourcePackageVersion),
			value(cve.GardenlinuxVersion),
			cve.BaseScore,
			vuln,
			value(cve.CvePublishedDate),
		)
	}
	fmt.Println()
}

type CveContext struct {
	ID            int     `json:"id"`
	CveId         string  `json:"cveId"`
	DistId        int     `json:"distId"`
	CreateDate    string  `json:"createDate"`
	UseCase       string  `json:"useCase"`
	ScoreOverride float32 `json:"scoreOverride"`
	Description   string  `json:"description"`
	Resolved      bool    `json:"resolved"`
}

type CveDetailsWithContext struct {
	Details  CveDetail    `json:"details"`
	Contexts []CveContext `json:"contexts"`
}

func printCveDetails(details CveDetailsWithContext) {
	// Define color styles
	header := color.New(color.FgHiCyan, color.Bold).SprintFunc()
	label := color.New(color.FgHiYellow, color.Bold).SprintFunc()
	value := color.New(color.FgHiWhite).SprintFunc()
	important := color.New(color.FgHiRed, color.Bold).SprintFunc()

	d := details.Details
	fmt.Println(header("=== CVE Details ==="))
	fmt.Printf("%s: %s\n", label("CVE ID"), value(d.CveId))
	fmt.Printf("%s: %s\n", label("Status"), value(d.VulnStatus))
	fmt.Printf("%s: %s\n", label("Description"), value(d.Description))
	fmt.Printf("%s: %s\n", label("Published"), value(d.CvePublishedDate))
	fmt.Printf("%s: %s\n", label("Modified"), value(d.CveModifiedDate))
	fmt.Printf("%s: %s\n", label("Ingested"), value(d.CveIngestedDate))
	fmt.Printf("%s: %v\n", label("Kernel LTS Versions"), value(d.KernelLtsVersion))
	fmt.Printf("%s: %v\n", label("Kernel Fixed Versions"), value(d.KernelFixedVersion))
	fmt.Printf("%s: %v\n", label("Kernel Is Fixed"), value(d.KernelIsFixed))
	fmt.Printf("%s: %v\n", label("Kernel Is Relevant Subsystem"), value(d.KernelIsRelevantSubsystem))
	// Print combined table of related fields
	maxLen := len(d.Distro)
	if len(d.DistroVersion) > maxLen {
		maxLen = len(d.DistroVersion)
	}
	if len(d.IsVulnerable) > maxLen {
		maxLen = len(d.IsVulnerable)
	}
	if len(d.SourcePackageName) > maxLen {
		maxLen = len(d.SourcePackageName)
	}
	if len(d.SourcePackageVersion) > maxLen {
		maxLen = len(d.SourcePackageVersion)
	}
	if len(d.VersionFixed) > maxLen {
		maxLen = len(d.VersionFixed)
	}

	fmt.Println(header("=== Per-Distro/Package Details ==="))
	fmt.Printf("%-25s %-18s %-10s %-25s %-25s %-20s\n",
		label("Distro"),
		label("Version"),
		label("Vuln?"),
		label("SourcePkg"),
		label("SourceVer"),
		label("VersionFixed"),
	)
	for i := 0; i < maxLen; i++ {
		distro := ""
		if i < len(d.Distro) {
			distro = d.Distro[i]
		}
		distroVer := ""
		if i < len(d.DistroVersion) {
			distroVer = d.DistroVersion[i]
		}
		vuln := ""
		if i < len(d.IsVulnerable) {
			if d.IsVulnerable[i] {
				vuln = important("YES")
			} else {
				vuln = value("no")
			}
		}
		srcPkg := ""
		if i < len(d.SourcePackageName) {
			srcPkg = d.SourcePackageName[i]
		}
		srcVer := ""
		if i < len(d.SourcePackageVersion) {
			srcVer = d.SourcePackageVersion[i]
		}
		verFixed := ""
		if i < len(d.VersionFixed) {
			verFixed = d.VersionFixed[i]
		}
		fmt.Printf("%-25s %-18s %-10s %-25s %-25s %-20s\n",
			value(distro),
			value(distroVer),
			vuln,
			value(srcPkg),
			value(srcVer),
			value(verFixed),
		)
	}
	fmt.Printf("%s: %s\n", label("Base Score V4.0"), value(d.BaseScoreV40))
	fmt.Printf("%s: %s\n", label("Base Score V3.1"), value(d.BaseScoreV31))
	fmt.Printf("%s: %s\n", label("Base Score V3.0"), value(d.BaseScoreV30))
	fmt.Printf("%s: %s\n", label("Base Score V2"), value(d.BaseScoreV2))
	fmt.Printf("%s: %s\n", label("Vector String V4.0"), value(d.VectorStringV40))
	fmt.Printf("%s: %s\n", label("Vector String V3.1"), value(d.VectorStringV31))
	fmt.Printf("%s: %s\n", label("Vector String V3.0"), value(d.VectorStringV30))
	fmt.Printf("%s: %s\n", label("Vector String V2"), value(d.VectorStringV2))
	fmt.Println()

	if len(details.Contexts) > 0 {
		fmt.Println(header("=== Contexts ==="))
		for i, ctx := range details.Contexts {
			fmt.Printf("%s #%d:\n", label("Context"), i+1)
			fmt.Printf("  %s: %d\n", label("ID"), ctx.ID)
			fmt.Printf("  %s: %s\n", label("CVE ID"), ctx.CveId)
			fmt.Printf("  %s: %d\n", label("Dist ID"), ctx.DistId)
			fmt.Printf("  %s: %s\n", label("Create Date"), ctx.CreateDate)
			fmt.Printf("  %s: %s\n", label("Use Case"), ctx.UseCase)
			fmt.Printf("  %s: %.2f\n", label("Score Override"), ctx.ScoreOverride)
			fmt.Printf("  %s: %s\n", label("Description"), ctx.Description)
			fmt.Printf("  %s: %v\n", label("Resolved"), ctx.Resolved)
			fmt.Println()
		}
	} else {
		fmt.Println(important("No context information available."))
	}
}

func versionList(ctx context.Context, cmd *cli.Command) error {
	url := "https://glvd.ingress.glvd.gardnlinux.shoot.canary.k8s-hana.ondemand.com/v1/gardenlinuxVersions"
	req, _ := http.NewRequest("GET", url, nil)

	res, _ := http.DefaultClient.Do(req)

	var results []string
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)

	err := json.Unmarshal(body, &results)
	if err != nil {
		log.Fatal(err)
	}

	if len(results) == 0 {
		fmt.Println("No Garden Linux versions found.")
		return nil
	}
	header := color.New(color.FgHiCyan, color.Bold).SprintFunc()
	value := color.New(color.FgHiWhite).SprintFunc()
	fmt.Println(header("Garden Linux Versions:"))
	for _, v := range results {
		fmt.Println("  " + value(v))
	}

	return nil
}

func cveList(ctx context.Context, cmd *cli.Command) error {
	url := "https://glvd.ingress.glvd.gardnlinux.shoot.canary.k8s-hana.ondemand.com/v1/cves/" + cmd.Args().Get(0)
	req, _ := http.NewRequest("GET", url, nil)

	res, _ := http.DefaultClient.Do(req)

	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)

	var results []sourcePackageCve
	err := json.Unmarshal(body, &results)
	if err != nil {
		log.Fatal(err)
	}

	printSourcePackageCveTable(results)
	return nil
}

func cveShow(ctx context.Context, cmd *cli.Command) error {
	url := "https://glvd.ingress.glvd.gardnlinux.shoot.canary.k8s-hana.ondemand.com/v1/cveDetails/" + cmd.Args().Get(0)
	req, _ := http.NewRequest("GET", url, nil)

	res, _ := http.DefaultClient.Do(req)

	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)

	var results CveDetailsWithContext
	err := json.Unmarshal(body, &results)
	if err != nil {
		log.Fatal(err)
	}

	printCveDetails(results)

	return nil
}

func main() {
	cmd := &cli.Command{
		Name:                  "glvdctl",
		EnableShellCompletion: true,
		Commands: []*cli.Command{
			{
				Name:    "version",
				Aliases: []string{},
				Usage:   "list Garden Linux releases known in GLVD",
				Commands: []*cli.Command{
					{
						Name:   "list",
						Usage:  "list Garden Linux releases known in GLVD",
						Action: versionList,
					},
				},
			},

			{
				Name:    "cve",
				Aliases: []string{"cves"},
				Usage:   "inspect CVEs known to GLVD",
				Commands: []*cli.Command{
					{
						Name:   "list",
						Usage:  "list known CVEs for this Garden Linux version",
						Action: cveList,
					},
					{
						Name:   "show",
						Usage:  "show details about this CVE",
						Action: cveShow,
					},
				},
			},
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}

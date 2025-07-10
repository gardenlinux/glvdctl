package main

import (
	"context"
	"encoding/json"
	"errors"
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
	IsVulnerable         bool    `json:"vulnerable"`
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
	important := color.New(color.FgHiRed, color.Bold).SprintFunc()

	cvssCritical := color.New(color.FgHiRed, color.Bold).SprintFunc()
	cvssHigh := color.New(color.FgHiMagenta, color.Bold).SprintFunc()
	cvssMedium := color.New(color.FgHiYellow, color.Bold).SprintFunc()

	fmt.Printf("%-18s %-4s %-4s %-46s %-20s %-20s\n", "CVE ID", "Vuln", "Score", "Vector String", "Source Package", "Version")
	for _, cve := range cves {
		vuln := "no"
		if cve.IsVulnerable {
			vuln = important("YES")
		}
		baseScore := ""
		if cve.BaseScore >= 9 {
			baseScore = cvssCritical(fmt.Sprintf("%4.1f", cve.BaseScore))
		} else if cve.BaseScore >= 7 {
			baseScore = cvssHigh(fmt.Sprintf("%4.1f", cve.BaseScore))
		} else if cve.BaseScore >= 4 {
			baseScore = cvssMedium(fmt.Sprintf("%4.1f", cve.BaseScore))
		} else if cve.BaseScore >= 0.1 {
			baseScore = fmt.Sprintf("%4.1f", cve.BaseScore)
		}
		fmt.Printf("%-18s %-4s %-4s %-46s %-20s %-20s\n", cve.CveId, vuln, baseScore, cve.VectorString, cve.SourcePackageName, cve.SourcePackageVersion)
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
	fixed := color.New(color.FgHiGreen, color.Bold).SprintFunc()

	d := details.Details
	fmt.Println(header("=== CVE Details ==="))
	fmt.Printf("%s: %s\n", label("CVE ID"), value(d.CveId))
	fmt.Printf("%s: %s\n", label("Status"), value(d.VulnStatus))
	fmt.Printf("%s: %s\n", label("Description"), value(d.Description))
	fmt.Printf("%s: %s\n", label("Published"), value(d.CvePublishedDate))
	fmt.Printf("%s: %s\n", label("Modified"), value(d.CveModifiedDate))
	fmt.Printf("%s: %s\n", label("Ingested"), value(d.CveIngestedDate))
	// Print combined table of kernel-related fields
	maxKernelLen := len(d.KernelLtsVersion)
	if len(d.KernelFixedVersion) > maxKernelLen {
		maxKernelLen = len(d.KernelFixedVersion)
	}
	if len(d.KernelIsFixed) > maxKernelLen {
		maxKernelLen = len(d.KernelIsFixed)
	}
	if len(d.KernelIsRelevantSubsystem) > maxKernelLen {
		maxKernelLen = len(d.KernelIsRelevantSubsystem)
	}

	if maxKernelLen > 0 {
		fmt.Println(header("=== Kernel Details ==="))
		fmt.Printf("%-20s %-20s %-10s %-20s\n",
			label("LTS Version"),
			label("Fixed Version"),
			label("Is Fixed"),
			label("Relevant Subsystem"),
		)
		for i := 0; i < maxKernelLen; i++ {
			ltsVer := ""
			if i < len(d.KernelLtsVersion) {
				ltsVer = d.KernelLtsVersion[i]
			}
			fixedVer := ""
			if i < len(d.KernelFixedVersion) {
				fixedVer = d.KernelFixedVersion[i]
			}
			isFixed := ""
			if i < len(d.KernelIsFixed) {
				if d.KernelIsFixed[i] {
					isFixed = fixed("YES")
				} else {
					isFixed = important("NO")
				}
			}
			isRelevant := ""
			if i < len(d.KernelIsRelevantSubsystem) {
				if d.KernelIsRelevantSubsystem[i] {
					isRelevant = important("YES")
				} else {
					isRelevant = value("no")
				}
			}
			fmt.Printf("%-20s %-22s %-22s %-20s\n",
				value(ltsVer),
				value(fixedVer),
				isFixed,
				isRelevant,
			)
		}
	}
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
	fmt.Printf("%-30s %-18s %-10s %-30s %-30s %-20s\n",
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
	// Print combined table of base scores and vector strings
	fmt.Println(header("=== CVSS Scores & Vectors ==="))
	fmt.Printf("%-18s %-12s %-46s\n",
		label("Version"),
		label("Base Score"),
		label("Vector String"),
	)
	cvssRows := []struct {
		Version      string
		BaseScore    float32
		VectorString string
	}{
		{"V4.0", d.BaseScoreV40, d.VectorStringV40},
		{"V3.1", d.BaseScoreV31, d.VectorStringV31},
		{"V3.0", d.BaseScoreV30, d.VectorStringV30},
		{"V2", d.BaseScoreV2, d.VectorStringV2},
	}
	for _, row := range cvssRows {
		scoreStr := ""
		if row.BaseScore > 0 {
			scoreStr = fmt.Sprintf("%.1f", row.BaseScore)
		}
		fmt.Printf("%-18s %-12s %-46s\n",
			value(row.Version),
			value(scoreStr),
			value(row.VectorString),
		)
	}
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
		fmt.Println(value("No context information available."))
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
	glVersion := cmd.Args().Get(0)
	if glVersion == "" {
		return errors.New("expected Garden Linux version as positional argument")
	}
	url := "https://glvd.ingress.glvd.gardnlinux.shoot.canary.k8s-hana.ondemand.com/v1/cves/" + glVersion
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
	cveId := cmd.Args().Get(0)
	if cveId == "" {
		return errors.New("expected CVE ID as positional argument")
	}
	url := "https://glvd.ingress.glvd.gardnlinux.shoot.canary.k8s-hana.ondemand.com/v1/cveDetails/" + cveId
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

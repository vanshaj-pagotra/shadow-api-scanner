package report

import (
	"fmt"
	"html/template"
	"os"
	"sort"
	"strings"
	"time"

	"shadow-api-scanner/engine"
)

// DocumentedGroup holds a list of endpoints grouped by their OpenAPI tag
type DocumentedGroup struct {
	Tag  string
	Rows []FindingRow
}

// ReportData holds everything the HTML template needs to render
type ReportData struct {
	Timestamp        string
	SpecFile         string
	LogFile          string
	TotalEntries     int
	TotalFindings    int
	DocumentedCount  int
	DocumentedGroups []DocumentedGroup
	ShadowRows       []FindingRow
}

// FindingRow wraps a Finding with a computed risk level for display
type FindingRow struct {
	engine.Finding
	RiskLevel string
	RiskColor string
}

// assessRisk assigns a risk level based on the OWASP Category
func assessRisk(f engine.Finding) (string, string) {
	if strings.HasPrefix(f.OWASPCategory, "API1") || strings.HasPrefix(f.OWASPCategory, "API5") || strings.HasPrefix(f.OWASPCategory, "API8") {
		return "HIGH", "#dc2626"
	}
	if strings.HasPrefix(f.OWASPCategory, "API9") {
		return "MEDIUM", "#ca8a04"
	}
	return "LOW", "#16a34a"
}

// Generate writes the HTML report to the given output path
func Generate(outputPath, specFile, logFile string, entries int, findings []engine.Finding) error {
	var shadowRows []FindingRow
	docMap := make(map[string][]FindingRow)
	docCount := 0

	for _, f := range findings {
		if f.IsDocumented {
			tag := f.Tag
			if tag == "" {
				tag = "Default"
			}
			docMap[tag] = append(docMap[tag], FindingRow{Finding: f})
			docCount++
		} else {
			level, color := assessRisk(f)
			shadowRows = append(shadowRows, FindingRow{
				Finding:   f,
				RiskLevel: level,
				RiskColor: color,
			})
		}
	}

	var docGroups []DocumentedGroup
	for tag, rows := range docMap {
		// Sort rows by path alphabetically for cleaner UI
		sort.Slice(rows, func(i, j int) bool {
			return rows[i].Path < rows[j].Path
		})
		docGroups = append(docGroups, DocumentedGroup{
			Tag:  tag,
			Rows: rows,
		})
	}

	// Sort groups alphabetically by Tag
	sort.Slice(docGroups, func(i, j int) bool {
		return docGroups[i].Tag < docGroups[j].Tag
	})

	data := ReportData{
		Timestamp:        time.Now().Format("2006-01-02 15:04:05"),
		SpecFile:         specFile,
		LogFile:          logFile,
		TotalEntries:     entries,
		TotalFindings:    len(shadowRows),
		DocumentedCount:  docCount,
		DocumentedGroups: docGroups,
		ShadowRows:       shadowRows,
	}

	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("could not parse report template: %w", err)
	}

	// Ensure the output directory exists
	outDir := outputPath
	lastSlash := strings.LastIndexAny(outputPath, "/\\")
	if lastSlash != -1 {
		outDir = outputPath[:lastSlash]
		if err := os.MkdirAll(outDir, 0755); err != nil {
			return fmt.Errorf("could not create output directory: %w", err)
		}
	}

	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("could not create output file: %w", err)
	}
	defer f.Close()

	return tmpl.Execute(f, data)
}

var htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Shadow API Scanner — Report</title>
  <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap">
  <style>

    /* --- reset --- */
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }

    body {
      background-color: #f8fafc;
      color: #334155;
      font-family: 'Inter', sans-serif;
      font-size: 14px;
      line-height: 1.6;
      min-height: 100vh;
    }

    /* --- layout & panels --- */
    .container {
      max-width: 1200px;
      margin: 0 auto;
      padding: 0 24px;
    }

    .header-panel {
      background: #ffffff;
      border-bottom: 1px solid #e2e8f0;
      padding: 40px 0;
      box-shadow: 0 1px 2px rgba(0,0,0,0.02);
    }

    .header h1 {
      font-size: 28px;
      font-weight: 700;
      color: #0f172a;
      letter-spacing: -0.5px;
    }

    .header h1 span {
      color: #2563eb;
    }

    .header p {
      color: #64748b;
      font-size: 14px;
      margin-top: 6px;
      margin-bottom: 24px;
    }

    /* --- meta pills --- */
    .meta {
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
    }

    .meta-item {
      background: #f1f5f9;
      border: 1px solid #e2e8f0;
      border-radius: 8px;
      padding: 8px 14px;
    }

    .meta-item label {
      display: block;
      font-size: 10px;
      font-weight: 600;
      letter-spacing: 1px;
      text-transform: uppercase;
      color: #64748b;
      margin-bottom: 2px;
    }

    .meta-item span {
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
      font-weight: 500;
      color: #334155;
    }

    /* --- stat cards --- */
    .stats {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 20px;
      padding: 32px 0;
    }

    .stat-card {
      background: #ffffff;
      border: 1px solid #e2e8f0;
      border-radius: 12px;
      padding: 24px;
      position: relative;
      overflow: hidden;
      box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05), 0 2px 4px -1px rgba(0, 0, 0, 0.03);
    }

    .stat-card::before {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 4px;
    }

    .stat-card.total::before  { background: #3b82f6; }
    .stat-card.shadow::before { background: #ef4444; }
    .stat-card.safe::before   { background: #10b981; }

    .stat-card h3 {
      font-size: 12px;
      font-weight: 600;
      letter-spacing: 1px;
      text-transform: uppercase;
      color: #64748b;
    }

    .stat-card .value {
      font-size: 36px;
      font-weight: 700;
      color: #0f172a;
      margin-top: 8px;
      line-height: 1;
    }

    .stat-card .value.danger { color: #dc2626; }
    .stat-card .value.safe   { color: #059669; }

    /* --- tabs --- */
    .tabs-wrapper {
      border-bottom: 1px solid #e2e8f0;
      margin-bottom: 32px;
    }

    .tabs {
      display: flex;
      gap: 32px;
    }

    .tab-btn {
      background: transparent;
      border: none;
      color: #64748b;
      font-size: 15px;
      font-weight: 600;
      padding: 16px 0;
      cursor: pointer;
      border-bottom: 3px solid transparent;
      transition: all 0.2s ease;
    }

    .tab-btn:hover {
      color: #0f172a;
    }

    .tab-btn.active {
      color: #2563eb;
      border-bottom-color: #2563eb;
    }

    .tab-content {
      display: none;
      padding-bottom: 64px;
    }

    .tab-content.active {
      display: block;
      animation: fadeIn 0.3s ease;
    }

    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(5px); }
      to { opacity: 1; transform: translateY(0); }
    }

    /* --- Tag Groups (Swagger style) --- */
    .tag-group {
      margin-bottom: 32px;
      background: #ffffff;
      border: 1px solid #e2e8f0;
      border-radius: 12px;
      box-shadow: 0 1px 3px rgba(0,0,0,0.05);
      overflow: hidden;
    }

    .tag-title {
      font-size: 18px;
      font-weight: 700;
      color: #0f172a;
      padding: 16px 24px;
      background: #f8fafc;
      border-bottom: 1px solid #e2e8f0;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    /* --- Endpoints UI --- */
    .endpoints {
      display: flex;
      flex-direction: column;
    }

    .endpoint-row {
      display: flex;
      align-items: center;
      padding: 14px 24px;
      border-bottom: 1px solid #f1f5f9;
      background: #ffffff;
      transition: background 0.15s;
    }

    .endpoint-row:last-child {
      border-bottom: none;
    }

    .endpoint-row:hover {
      background: #f8fafc;
    }

    .endpoint-row.shadow-row {
      background: #fef2f2;
      border-bottom: 1px solid #fee2e2;
    }
    
    .endpoint-row.shadow-row:hover {
      background: #fee2e2;
    }

    /* Method Badges */
    .method {
      font-family: 'Inter', sans-serif;
      font-size: 12px;
      font-weight: 700;
      padding: 4px 12px;
      border-radius: 6px;
      width: 80px;
      text-align: center;
      margin-right: 16px;
      flex-shrink: 0;
    }

    .method.GET    { background: #eff6ff; color: #2563eb; border: 1px solid #bfdbfe; }
    .method.POST   { background: #f0fdf4; color: #16a34a; border: 1px solid #bbf7d0; }
    .method.DELETE { background: #fef2f2; color: #dc2626; border: 1px solid #fecaca; }
    .method.PUT    { background: #fffbeb; color: #d97706; border: 1px solid #fde68a; }
    .method.PATCH  { background: #faf5ff; color: #9333ea; border: 1px solid #e9d5ff; }

    /* Path */
    .path {
      font-family: 'JetBrains Mono', monospace;
      font-size: 14px;
      font-weight: 600;
      color: #334155;
      margin-right: 24px;
      white-space: nowrap;
    }

    /* Summary text */
    .summary {
      font-size: 13px;
      color: #64748b;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      flex-grow: 1;
    }

    /* Risk Badge */
    .risk-badge {
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.5px;
      text-transform: uppercase;
      padding: 4px 12px;
      border-radius: 20px;
      margin-right: 24px;
    }

    .owasp {
      font-weight: 600;
      color: #dc2626;
      font-size: 13px;
    }

    /* --- empty state --- */
    .empty {
      text-align: center;
      padding: 64px 24px;
      background: #ffffff;
      border: 1px dashed #cbd5e1;
      border-radius: 12px;
      margin-top: 32px;
    }

    /* --- Search Bar --- */
    .search-wrapper {
      margin-bottom: 24px;
      position: relative;
    }
    
    .search-input {
      width: 100%;
      padding: 12px 16px;
      padding-left: 40px;
      font-size: 15px;
      border: 1px solid #cbd5e1;
      border-radius: 8px;
      background: #ffffff;
      transition: border-color 0.2s, box-shadow 0.2s;
    }
    
    .search-input:focus {
      outline: none;
      border-color: #3b82f6;
      box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
    }

    .search-icon {
      position: absolute;
      left: 14px;
      top: 50%;
      transform: translateY(-50%);
      color: #94a3b8;
    }

    .empty h3 {
      font-size: 18px;
      font-weight: 600;
      color: #0f172a;
      margin-bottom: 8px;
    }

    .empty p {
      color: #64748b;
      font-size: 14px;
    }

    /* --- footer --- */
    .footer {
      text-align: center;
      padding: 32px 0;
      color: #94a3b8;
      font-size: 13px;
      border-top: 1px solid #e2e8f0;
      margin-top: 32px;
    }

  </style>
</head>

<body>

  <div class="header-panel">
    <div class="container header">
      <h1>Shadow <span>API</span> Scanner</h1>
      <p>Automated Shadow API discovery</p>
      <div class="meta">
        <div class="meta-item">
          <label>Scan Time</label>
          <span>{{.Timestamp}}</span>
        </div>
        <div class="meta-item">
          <label>Spec File</label>
          <span>{{.SpecFile}}</span>
        </div>
        <div class="meta-item">
          <label>Log File</label>
          <span>{{.LogFile}}</span>
        </div>
      </div>
    </div>
  </div>

  <div class="container">
    <div class="stats">
      <div class="stat-card total">
        <h3>Log Entries Scanned</h3>
        <div class="value">{{.TotalEntries}}</div>
      </div>
      <div class="stat-card shadow">
        <h3>Shadow APIs Found</h3>
        <div class="value {{if gt .TotalFindings 0}}danger{{else}}safe{{end}}">{{.TotalFindings}}</div>
      </div>
      <div class="stat-card safe">
        <h3>Documented Endpoints</h3>
        <div class="value safe">{{.DocumentedCount}}</div>
      </div>
    </div>

    <div class="tabs-wrapper">
      <div class="tabs">
        <button class="tab-btn active" onclick="showTab('documented', this)">Documented APIs ({{.DocumentedCount}})</button>
        <button class="tab-btn" onclick="showTab('shadow', this)">Shadow APIs ({{.TotalFindings}})</button>
      </div>
    </div>

    <div class="search-wrapper">
      <svg class="search-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
      <input type="text" id="searchInput" class="search-input" placeholder="Search API paths, methods, tags or summaries..." onkeyup="filterEndpoints()">
    </div>

    <!-- DOCUMENTED TAB -->
    <div class="tab-content active" id="documented">
      {{if .DocumentedGroups}}
        {{range .DocumentedGroups}}
        <div class="tag-group">
          <h3 class="tag-title">{{.Tag}}</h3>
          <div class="endpoints">
            {{range .Rows}}
            <div class="endpoint-row">
              <span class="method {{.Method}}">{{.Method}}</span>
              <span class="path">{{.Path}}</span>
              {{if .Summary}}<span class="summary">{{.Summary}}</span>{{end}}
            </div>
            {{end}}
          </div>
        </div>
        {{end}}
      {{else}}
        <div class="empty">
          <h3>No Documented APIs Found</h3>
        </div>
      {{end}}
    </div>

    <!-- SHADOW TAB -->
    <div class="tab-content" id="shadow">
      {{if .ShadowRows}}
      <div class="tag-group">
        <h3 class="tag-title" style="color: #dc2626;">Undocumented Endpoints Detected</h3>
        <div class="endpoints">
          {{range .ShadowRows}}
          <div class="endpoint-row shadow-row">
            <span class="method {{.Method}}">{{.Method}}</span>
            <span class="path">{{.Path}}</span>
            <span class="risk-badge" style="background: {{.RiskColor}}22; color: {{.RiskColor}}; border: 1px solid {{.RiskColor}}55;">
              {{.RiskLevel}}
            </span>
            <span class="owasp">{{.OWASPCategory}}</span>
          </div>
          {{end}}
        </div>
      </div>
      {{else}}
      <div class="empty">
        <h3>No Shadow APIs Detected</h3>
        <p>All active endpoints are documented in the provided specification.</p>
      </div>
      {{end}}
    </div>

    <div class="footer">
      Generated by Shadow API Scanner
    </div>
  </div>

  <script>
    function showTab(tabId, btn) {
        document.querySelectorAll('.tab-content').forEach(function(el) { el.classList.remove('active'); });
        document.querySelectorAll('.tab-btn').forEach(function(el) { el.classList.remove('active'); });
        document.getElementById(tabId).classList.add('active');
        btn.classList.add('active');
    }

    function filterEndpoints() {
        var input = document.getElementById("searchInput");
        var filter = input.value.toLowerCase();
        var rows = document.getElementsByClassName("endpoint-row");
        
        for (var i = 0; i < rows.length; i++) {
            var rowText = rows[i].textContent || rows[i].innerText;
            if (rowText.toLowerCase().indexOf(filter) > -1) {
                rows[i].style.display = "";
            } else {
                rows[i].style.display = "none";
            }
        }
        
        var groups = document.getElementsByClassName("tag-group");
        for (var j = 0; j < groups.length; j++) {
            var visibleRows = groups[j].querySelectorAll('.endpoint-row:not([style*="display: none"])');
            if (visibleRows.length === 0) {
                groups[j].style.display = "none";
            } else {
                groups[j].style.display = "";
            }
        }
    }
  </script>
</body>
</html>`

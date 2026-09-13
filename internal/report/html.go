package report

import (
	"html/template"
	"sort"
	"strings"
)

// HTML renders the report as one self-contained page — a deliverable you can
// attach to a ticket or hand to a reviewer, not a terminal dump.
//
// No external assets: all CSS inline, system font stacks, no network, and no
// JavaScript at all. The tabs are CSS-only (hidden radio inputs plus the sibling
// combinator), which keeps them keyboard-navigable and means the page works
// offline, inside an email client, and under a strict CSP.
//
// Light and dark both, following the reader's OS preference — an on-call
// engineer opening this at 3am should not be flash-banged.
func (r *Report) HTML() string {
	r.Sort()
	data := r.htmlModel()
	var b strings.Builder
	if err := htmlTmpl.Execute(&b, data); err != nil {
		// Templating a fixed template over validated data should not fail. If it
		// somehow does, degrade to the text report rather than emitting nothing.
		return "<pre>" + template.HTMLEscapeString(r.Text(0)) + "</pre>"
	}
	return b.String()
}

type htmlFinding struct {
	Index                             int
	Severity, Category, Rule, Message string
	Location, Fix                     string
	Prose, Before, After              string
}

type htmlCategory struct {
	Name, ID string
	Count    int
	Findings []htmlFinding
}

type htmlModel struct {
	Tool, Subject, Scanned string
	Total                  int
	Verdict, VerdictClass  string
	Counts                 []htmlCount
	Categories             []htmlCategory
	Cost                   *Cost
	Capped                 int // 0 = nothing hidden
}

type htmlCount struct {
	Label string
	N     int
	Class string
}

// maxPerTab bounds the page so a repository with thousands of findings still
// renders fast. The banner states the real total, so a capped page never reads
// as a complete one.
const maxPerTab = 50

func (r *Report) htmlModel() htmlModel {
	m := htmlModel{Tool: r.Tool, Subject: r.Subject, Scanned: r.Scanned, Total: len(r.Findings)}

	counts := r.Counts()
	for _, s := range []Severity{Critical, High, Medium, Low, Info} {
		if counts[s] > 0 {
			m.Counts = append(m.Counts, htmlCount{Label: string(s), N: counts[s], Class: string(s)})
		}
	}

	switch worst := r.Worst(); {
	case worst == "":
		m.Verdict, m.VerdictClass = "No findings. Deterministic checks only — a clean report is not a proof of safety.", "ok"
	case worst == Critical || worst == High:
		m.Verdict, m.VerdictClass = "Urgent issues found — deal with the top of this list before anything else.", "bad"
	default:
		m.Verdict, m.VerdictClass = "No urgent issue. What follows is worth scheduling, not worth paging anyone.", "warn"
	}

	// One tab per category, plus "All" first. A category with nothing in it is
	// not shown: an empty tab is a dead end.
	byCat := map[string][]Finding{}
	var catOrder []string
	for _, f := range r.Findings {
		c := f.Category
		if c == "" {
			c = "findings"
		}
		if _, seen := byCat[c]; !seen {
			catOrder = append(catOrder, c)
		}
		byCat[c] = append(byCat[c], f)
	}
	sort.Strings(catOrder)

	m.Categories = append(m.Categories, htmlCategory{
		Name: "All", ID: "all", Count: len(r.Findings), Findings: r.htmlFindings(r.Findings),
	})
	for _, c := range catOrder {
		m.Categories = append(m.Categories, htmlCategory{
			Name: strings.Title(c), ID: slug(c), Count: len(byCat[c]), Findings: r.htmlFindings(byCat[c]),
		})
	}
	if len(r.Findings) > maxPerTab {
		m.Capped = maxPerTab
	}
	if !r.Cost.Zero() {
		c := r.Cost
		m.Cost = &c
	}
	return m
}

func (r *Report) htmlFindings(fs []Finding) []htmlFinding {
	out := make([]htmlFinding, 0, len(fs))
	for i, f := range fs {
		if i >= maxPerTab {
			break
		}
		h := htmlFinding{
			Index: i + 1, Severity: strings.ToLower(string(f.Severity)),
			Category: f.Category, Rule: f.Rule, Message: f.Message,
			Location: f.Location(), Fix: f.Fix,
		}
		if e, ok := r.Enriched[f.ID()]; ok {
			h.Prose, h.Before, h.After = e.Prose, e.Before, e.After
		}
		out = append(out, h)
	}
	return out
}

func slug(s string) string {
	s = strings.ToLower(s)
	s = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return r
		}
		return '-'
	}, s)
	return strings.Trim(s, "-")
}

var htmlTmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"add": func(a, b int) int { return a + b },
}).Parse(`<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Tool}} — {{.Subject}}</title>
<style>
  :root {
    --bg:#ffffff; --fg:#1a1a1a; --muted:#6b7280; --line:#e5e7eb; --card:#f9fafb;
    --critical:#b91c1c; --high:#dc2626; --medium:#d97706; --low:#2563eb; --info:#6b7280;
    --ok:#059669;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg:#0f1115; --fg:#e5e7eb; --muted:#9ca3af; --line:#262b33; --card:#161a21;
      --critical:#f87171; --high:#f87171; --medium:#fbbf24; --low:#60a5fa; --info:#9ca3af;
      --ok:#34d399;
    }
  }
  *{box-sizing:border-box}
  body{margin:0;padding:2rem 1rem;background:var(--bg);color:var(--fg);
       font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}
  .wrap{max-width:60rem;margin:0 auto}
  h1{font-size:1.5rem;margin:.2rem 0}
  .eyebrow{font-size:.72rem;letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}
  .sub{color:var(--muted);font-size:.9rem;margin:.15rem 0 1.2rem}
  .verdict{border-left:3px solid var(--medium);background:var(--card);padding:.8rem 1rem;
           border-radius:.4rem;margin:1.2rem 0}
  .verdict.bad{border-color:var(--high)} .verdict.ok{border-color:var(--ok)}
  .tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(7rem,1fr));gap:.6rem;margin:1.2rem 0}
  .tile{background:var(--card);border:1px solid var(--line);border-radius:.5rem;padding:.7rem .9rem}
  .tile b{display:block;font-size:1.6rem;font-variant-numeric:tabular-nums;line-height:1.1}
  .tile span{font-size:.7rem;letter-spacing:.06em;text-transform:uppercase;color:var(--muted)}
  .critical b{color:var(--critical)} .high b{color:var(--high)} .medium b{color:var(--medium)}
  .low b{color:var(--low)} .info b{color:var(--info)}
  /* CSS-only tabs: a hidden radio per tab, the sibling combinator reveals a panel.
     No JavaScript, so the page works offline and under a strict CSP. */
  .tabs{margin-top:1.5rem}
  .tabs input{position:absolute;opacity:0;pointer-events:none}
  .tabs label{display:inline-block;padding:.45rem .9rem;border:1px solid var(--line);
              border-bottom:none;border-radius:.4rem .4rem 0 0;cursor:pointer;font-size:.88rem;
              color:var(--muted);margin-right:.15rem}
  .tabs label .n{font-size:.72rem;background:var(--card);border-radius:.7rem;padding:.05rem .4rem;margin-left:.3rem}
  .tabs input:checked + label{color:var(--fg);border-color:var(--line);background:var(--card);font-weight:600}
  .tabs input:focus-visible + label{outline:2px solid var(--low);outline-offset:2px}
  .panel{display:none;border-top:1px solid var(--line);padding-top:1rem}
  {{range $i, $c := .Categories}}{{if $i}},{{end}}#t{{$i}}:checked ~ .panels #p{{$i}}{{end}} {display:block}
  .f{border-left:3px solid var(--line);background:var(--card);border-radius:.4rem;
     padding:.75rem 1rem;margin-bottom:.7rem}
  .f.critical,.f.high{border-color:var(--high)} .f.medium{border-color:var(--medium)}
  .f.low{border-color:var(--low)} .f.info{border-color:var(--info)}
  .f .head{display:flex;gap:.5rem;align-items:baseline;flex-wrap:wrap;margin-bottom:.35rem}
  .badge{font-size:.68rem;font-weight:700;letter-spacing:.05em;padding:.1rem .4rem;border-radius:.25rem;
         border:1px solid currentColor}
  .badge.critical,.badge.high{color:var(--high)} .badge.medium{color:var(--medium)}
  .badge.low{color:var(--low)} .badge.info{color:var(--info)}
  .rule{color:var(--muted);font-size:.8rem}
  .loc{margin-left:auto;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.8rem;color:var(--muted)}
  .fix{margin-top:.4rem;font-size:.88rem}
  .fix b{color:var(--ok)}
  pre{background:var(--bg);border:1px solid var(--line);border-radius:.35rem;padding:.6rem .8rem;
      overflow-x:auto;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.8rem;margin:.5rem 0 0}
  pre .del{color:var(--high)} pre .add{color:var(--ok)}
  footer{margin-top:2rem;padding-top:1rem;border-top:1px solid var(--line);
         color:var(--muted);font-size:.8rem}
</style></head>
<body><div class="wrap">
  <div class="eyebrow">{{.Tool}} report</div>
  <h1>{{.Subject}}</h1>
  {{if .Scanned}}<div class="sub">{{.Scanned}}</div>{{end}}

  <div class="verdict {{.VerdictClass}}">{{.Verdict}}</div>

  <div class="tiles">
    <div class="tile"><b>{{.Total}}</b><span>total</span></div>
    {{range .Counts}}<div class="tile {{.Class}}"><b>{{.N}}</b><span>{{.Label}}</span></div>{{end}}
  </div>

  <div class="tabs">
    {{range $i, $c := .Categories}}
    <input type="radio" name="tab" id="t{{$i}}"{{if eq $i 0}} checked{{end}}>
    <label for="t{{$i}}">{{$c.Name}}<span class="n">{{$c.Count}}</span></label>
    {{end}}
    <div class="panels">
      {{range $i, $c := .Categories}}
      <div class="panel" id="p{{$i}}">
        {{range $c.Findings}}
        <div class="f {{.Severity}}">
          <div class="head">
            <span class="badge {{.Severity}}">{{.Severity}}</span>
            {{if .Rule}}<span class="rule">{{.Rule}}</span>{{end}}
            <span class="loc">{{.Location}}</span>
          </div>
          <div>{{.Message}}</div>
          {{if .Prose}}<div class="fix">{{.Prose}}</div>{{end}}
          {{if or .Before .After}}<pre>{{if .Before}}<span class="del">{{.Before}}</span>{{end}}{{if .After}}<span class="add">{{.After}}</span>{{end}}</pre>{{end}}
          {{if .Fix}}<div class="fix"><b>fix:</b> {{.Fix}}</div>{{end}}
        </div>
        {{end}}
        {{if gt $c.Count 50}}<div class="sub">Showing the first 50 of {{$c.Count}} — run with --json for the full list.</div>{{end}}
      </div>
      {{end}}
    </div>
  </div>

  <footer>
    Generated by {{.Tool}} · deterministic checks{{if .Cost}}, plus one AI explanation call
    ({{.Cost.InputTokens}} in / {{.Cost.OutputTokens}} out tokens, ${{printf "%.4f" .Cost.USD}}, {{.Cost.Model}}){{end}}.<br>
    A clean report is not a proof of safety — these are heuristics, not a guarantee.
  </footer>
</div></body></html>
`))

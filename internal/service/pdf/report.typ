#let data = json("report.json")
#let zh = data.language == "zh"
#let tr(en, tc) = if zh { tc } else { en }
#let accent = rgb("#143442")
#let neutral = rgb("#eef2f3")
#let urgent = rgb("#801a24")
#let elevated = rgb("#754700")
#let priority-color(action) = if action.priority == "urgent" {
  urgent
} else if action.priority == "elevated" {
  elevated
} else {
  accent
}
#let muted = rgb("#495c68")

#set document(title: data.title)
#set text(font: ("Noto Sans CJK TC", "Noto Emoji", "SBOM Missing Glyph"), lang: tr("en", "zh"), region: tr("US", "TW"), fallback: false, cjk-latin-spacing: none, size: 9.5pt)
#set page(paper: "a4", margin: (x: 17mm, y: 18mm),
  header: pdf.artifact(text(size: 8pt, fill: muted, tr("ex-sbom | SBOM analysis", "ex-sbom | SBOM 分析"))),
  footer: context pdf.artifact(align(right, text(size: 8pt, fill: muted, tr("Page ", "頁次 ") + str(counter(page).get().first())))),
)
#set par(leading: 0.48em)
#show heading.where(level: 1): set text(fill: accent, size: 19pt, weight: "bold")
#show heading.where(level: 2): set text(fill: accent, size: 13pt, weight: "bold")
#show heading.where(level: 3): set text(size: 11pt, weight: "bold")
#let wrap(value, width: 24) = value.replace(regex("\\S{" + str(width + 1) + ",}"), match => {
  match.text.clusters().chunks(width).map(chunk => chunk.join()).join(sym.zws)
})
#let report-heading(title, color: black) = {
  show heading: it => block(above: 0.75em, below: 0.4em, sticky: true, text(fill: color, wrap(title)))
  heading(level: 3, title)
}
#let recorded(value) = if value == "" { tr("Not recorded", "未記錄") } else { value }
#let field(item, prose: false, sticky: false) = {
  let label = text(weight: "bold", item.label) + text(" ")
  let value = recorded(item.value)
  if prose and item.value != "" {
    block(above: 4pt, below: 4pt, sticky: true, par(text(weight: "bold", item.label)))
    block(above: 0pt, below: 4pt, par(text(lang: "en", region: none, wrap(value))))
  } else {
    block(above: 4pt, below: 4pt, sticky: sticky, par(label + text(wrap(value))))
  }
}
#let metric(label, value) = block(width: 100%, height: 18mm, inset: 3mm, fill: neutral)[
  #label \
  #text(size: 16pt, weight: "bold", value)
]
#let counts(action) = {
  field((label: tr("Cumulative findings expected to be addressed", "累計預計處理的元件弱點紀錄"), value: str(action.cumulative_count)))
  field((label: tr("CVEs expected to be addressed across all known affected components", "已知受影響元件均有方案的 CVE 數"), value: str(action.full_cve_count)))
  field((label: tr("Components still requiring immediate updates", "仍需立即更新的元件"), value: action.remaining_urgent))
}

#heading(level: 1, data.title)
#for item in data.metadata { field(item) }

== #tr("Remediation summary", "修補摘要")
#if data.warning != "" { par(data.warning) }
#if data.actions.len() == 0 {
  if data.empty_remediation != "" { par(data.empty_remediation) }
} else {
  grid(columns: (1fr, 1fr), gutter: 4mm,
    metric(tr("Components to update immediately", "需立即更新的元件"), data.urgent_components),
    metric(tr("CVEs listed in CISA KEV", "列入 CISA KEV 的弱點"), data.kev_count),
  )
  if data.needs_review > 0 {
    field((label: tr("Components with unclassified findings", "含未分級弱點的元件"), value: str(data.needs_review)))
  }
  if data.additional_urgent != "" {
    field((label: tr("Additional components to update immediately", "另有需立即更新的元件"), value: data.additional_urgent))
  }
  link(<remediation-order>, underline(tr("View remediation order", "查看修補順序表")))
  let first = data.actions.first()
  heading(level: 2, tr("Priority action", "優先交辦項目"))
  block(width: 100%, inset: 4mm, stroke: (left: 1.25mm + priority-color(first), rest: 0.35pt + rgb("#bac5cb")))[
    #report-heading(first.title, color: priority-color(first))
    #for item in first.fields { field(item) }
  ]
  heading(level: 2, tr("If only action 1 is completed", "若本輪只完成第 1 項"))
  if first.coverage_note != "" {
    par(first.coverage_note)
  }
  block(width: 100%, inset: 3mm, fill: neutral)[#counts(first)]
  pagebreak()
}
#if data.order_rows.len() > 0 {
  [== #tr("Remediation order", "修補順序表") <remediation-order>]
  par(data.order_note)
  table(columns: (13mm, 1fr, 21mm, 30mm, 28mm, 27mm), stroke: none, inset: 4pt,
    table.header(..data.order_headers.map(label => table.cell(fill: neutral)[#label])),
    ..data.order_rows.map(item => item.cells.enumerate().map(((i, value)) => {
      let value = wrap(value, width: if i == 1 { 12 } else { 6 })
      if i == 4 and item.urgent { text(fill: rgb("#801a24"), value) } else { value }
    })).flatten(),
  )
}
#if data.actions.len() > 1 {
  [== #tr("Remediation priorities (continued)", "修補處理順序（續）")]
  for action in data.actions.slice(1) {
    report-heading(action.title, color: priority-color(action))
    for item in action.fields { field(item) }
    counts(action)
  }
}
== #tr("Report information", "報告資訊")
#for item in data.evidence { field(item) }

== #tr("Analysis summary", "分析摘要")
#for item in data.summary { field(item) }

== #tr("Component inventory", "元件清單")
#if data.components.len() == 0 {
  tr("No component records.", "沒有元件紀錄")
} else {
  table(columns: (1fr, 29mm, 26mm, 18mm), stroke: none, inset: 4pt,
    table.header(..(tr("Component", "元件"), tr("Version", "版本"), tr("Scope", "類型"), tr("Findings", "弱點數")).map(label => table.cell(fill: neutral)[#label])),
    ..data.components.map(component => {
      let breakable = component.name.len() > 240 or component.version.len() > 240
      (
        table.cell(breakable: breakable)[#wrap(component.name)],
        table.cell(breakable: breakable)[#wrap(recorded(component.version), width: 8)],
        component.scope, str(component.count),
      )
    }).flatten(),
  )
}

== #tr("Vulnerability details", "弱點明細")
#if data.findings.len() == 0 {
  tr("No vulnerability records are stored for this version.", "此版本未儲存弱點紀錄")
}
#for finding in data.findings {
  report-heading(finding.title)
  field(finding.component, sticky: true)
  field(finding.version)
  field(finding.summary, prose: true)
  for item in finding.fields { field(item) }
  field(finding.details, prose: true)
}
#if data.has_missing_glyphs [
  == #tr("Text display note", "文字顯示說明")
  #tr(
    "Boxes mark characters that the report fonts cannot display. Copy or extract the text to recover the original characters.",
    "方框表示報告字型無法顯示的字元。可複製或擷取文字取得原始字元。",
  )
]

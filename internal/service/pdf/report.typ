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
#let field(item) = block(above: 4pt, below: 4pt)[
  #text(weight: "bold", item.label) #h(4pt) #item.value
]
#let row(item) = grid(
  columns: (31%, 1fr), gutter: 3mm,
  text(weight: "bold", item.label), item.value,
)
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
    field((label: tr("Components with findings to assess", "有待評估弱點的元件"), value: str(data.needs_review)))
  }
  if data.additional_urgent != "" {
    field((label: tr("Additional components to update immediately", "另有需立即更新的元件"), value: data.additional_urgent))
  }
  if data.actions.len() > 1 {
    link(<remaining-priorities>, underline(tr("See remaining remediation priorities", "查看其餘修補項目")))
  }
  let first = data.actions.first()
  heading(level: 2, tr("Priority action", "優先交辦項目"))
  block(width: 100%, inset: 4mm, stroke: (left: 1.25mm + priority-color(first), rest: 0.35pt + rgb("#bac5cb")))[
    #heading(level: 3, text(fill: priority-color(first), first.title))
    #for item in first.fields { row(item) }
  ]
  heading(level: 2, tr("If only action 1 is completed", "若本輪只完成第 1 項"))
  if first.coverage_note != "" {
    par(first.coverage_note)
  }
  block(width: 100%, inset: 3mm, fill: neutral)[#counts(first)]
  pagebreak()
}
#if data.actions.len() > 1 {
  [== #tr("Remediation priorities (continued)", "修補處理順序（續）") <remaining-priorities>]
  for action in data.actions.slice(1) {
    heading(level: 3, text(fill: priority-color(action), action.title))
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
    ..data.components.map(component => (table.cell(breakable: true)[#component.name], component.version, component.scope, str(component.count))).flatten(),
  )
}

== #tr("Vulnerability details", "弱點明細")
#if data.findings.len() == 0 {
  tr("No vulnerability records are stored for this version.", "此版本未儲存弱點紀錄")
}
#for finding in data.findings {
  heading(level: 3, finding.id)
  for item in finding.fields { field(item) }
}

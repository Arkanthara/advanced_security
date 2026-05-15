// Main report file
#import "template.typ": create-report-template

// Configure your report
#let my-report = create-report-template(
  // Required information
  logo: "./img/unige.svg",
  logosize: 6cm,
  university: "University of Geneva",
  title: "Timing Attacks",

  // Structured authors
  authors: (
    (
      name: "Michel Jean Joseph Donnet",
    ),
  ),

  // Optional information
  faculty: "Faculty of Science",
  // subtitle: "Report Subtitle",
  course-name: "Advanced Security",
  course-id: "14X040",
  illustrations: (
    (
      path: ".typst_pyexec/figures/cell_5_1_1.svg",
      width: 15cm,
    ),
    // (
    //   path: "./img/full_hist_R.png",
    //   width: 10cm,
    // ),
  ),
  project-name: "Computational Finance",
  date: none,

  // Document options
  toc: true,
  numbering: true,
  bibliography: "bibliography.bib",
  appendix: false,
)

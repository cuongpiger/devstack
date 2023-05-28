#!/usr/bin/sh

# [cuongdm]
# Troubleshotting
#   - Install latexmk: https://zoomadmin.com/HowToInstall/UbuntuPackage/latexmk
#   - Install xelatex: https://github.com/rstudio/bookdown/issues/292
#   - Install xindy: https://github.com/sphinx-doc/sphinx/issues/8941

generate_pdf_doc() {
  echo "Building the DevStack documentation"
  rm -rf doc/build/pdf
  sphinx-build -W --keep-going -b latex -j auto doc/source doc/build/pdf
  make -C doc/build/pdf
}

generate_pdf_doc
